//! Minimal Ethereum JSON-RPC client + EIP-1559 transaction signing + RLP encoding.
//!
//! Deliberately dependency-light: signing uses the existing `k256` key, requests use the
//! existing `reqwest` client, and RLP is implemented here. Enough to submit
//! `ReceiptAnchor.anchor(bytes32,bytes32,uint64)`.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::error::BrokerError;
use crate::merkle::keccak;
use crate::signer::{self, DigestSigner, LocalSigner};

// ── RLP ─────────────────────────────────────────────────────────────────────

pub enum Rlp<'a> {
    Bytes(&'a [u8]),
    List(Vec<Rlp<'a>>),
}

impl Rlp<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let payload = match self {
            Rlp::Bytes(bytes) => bytes.to_vec(),
            Rlp::List(items) => items.iter().flat_map(|i| i.encode()).collect(),
        };
        if let Rlp::Bytes(bytes) = self {
            if bytes.len() == 1 && bytes[0] < 0x80 {
                return payload;
            }
        }
        let mut out = Vec::with_capacity(payload.len() + 9);
        let base = if matches!(self, Rlp::Bytes(_)) {
            0x80
        } else {
            0xc0
        };
        if payload.len() < 56 {
            out.push(base + payload.len() as u8);
        } else {
            let len = minimal_be(payload.len() as u128);
            out.push(base + 55 + len.len() as u8);
            out.extend_from_slice(&len);
        }
        out.extend_from_slice(&payload);
        out
    }
}

/// Big-endian, no leading zero bytes (empty for 0).
pub fn minimal_be(value: u128) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

#[cfg(test)]
fn rlp_u128(v: u128) -> Vec<u8> {
    let bytes = minimal_be(v);
    Rlp::Bytes(&bytes).encode()
}

#[cfg(test)]
fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    Rlp::Bytes(b).encode()
}

// ── Signer ──────────────────────────────────────────────────────────────────

pub struct TxEip1559 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
}

pub struct EthSigner {
    backend: Arc<dyn DigestSigner>,
    address: [u8; 20],
}

impl EthSigner {
    pub fn from_hex(key_hex: &str) -> Result<Self, BrokerError> {
        Self::from_backend(Arc::new(LocalSigner::from_hex(key_hex)?))
    }

    /// Build from any signing backend (local key or KMS/HSM bridge).
    pub fn from_backend(backend: Arc<dyn DigestSigner>) -> Result<Self, BrokerError> {
        let address = parse_address(&backend.address_hex())?;
        Ok(Self { backend, address })
    }

    pub fn backend(&self) -> Arc<dyn DigestSigner> {
        self.backend.clone()
    }

    pub fn address_hex(&self) -> String {
        signer::address_hex(&self.address)
    }

    /// Sign a typed (EIP-1559) transaction; returns the raw `0x02…` hex.
    pub async fn sign_eip1559(&self, tx: &TxEip1559) -> Result<String, BrokerError> {
        let to_bytes = tx.to.map(|a| a.to_vec()).unwrap_or_default();
        let access_list: Vec<Rlp> = vec![];

        let unsigned = Rlp::List(vec![
            Rlp::Bytes(&minimal_be(tx.chain_id as u128)),
            Rlp::Bytes(&minimal_be(tx.nonce as u128)),
            Rlp::Bytes(&minimal_be(tx.max_priority_fee_per_gas)),
            Rlp::Bytes(&minimal_be(tx.max_fee_per_gas)),
            Rlp::Bytes(&minimal_be(tx.gas_limit as u128)),
            Rlp::Bytes(&to_bytes),
            Rlp::Bytes(&minimal_be(tx.value)),
            Rlp::Bytes(&tx.data),
            Rlp::List(access_list),
        ])
        .encode();

        let mut payload = vec![0x02u8];
        payload.extend_from_slice(&unsigned);
        let digest = keccak(&payload);

        let (r, s, recid) = self.backend.sign_prehash(&digest).await?;
        let r = strip_leading_zeros(&r);
        let s = strip_leading_zeros(&s);

        let signed = Rlp::List(vec![
            Rlp::Bytes(&minimal_be(tx.chain_id as u128)),
            Rlp::Bytes(&minimal_be(tx.nonce as u128)),
            Rlp::Bytes(&minimal_be(tx.max_priority_fee_per_gas)),
            Rlp::Bytes(&minimal_be(tx.max_fee_per_gas)),
            Rlp::Bytes(&minimal_be(tx.gas_limit as u128)),
            Rlp::Bytes(&to_bytes),
            Rlp::Bytes(&minimal_be(tx.value)),
            Rlp::Bytes(&tx.data),
            Rlp::List(vec![]),
            Rlp::Bytes(&minimal_be(recid as u128)),
            Rlp::Bytes(&r),
            Rlp::Bytes(&s),
        ])
        .encode();

        let mut raw = vec![0x02u8];
        raw.extend_from_slice(&signed);
        Ok(format!("0x{}", hex::encode(raw)))
    }
}

fn strip_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

// ── RPC ─────────────────────────────────────────────────────────────────────

pub struct RpcClient {
    url: String,
    http: reqwest::Client,
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            http: crate::netguard::outbound_client(),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, BrokerError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp: Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| BrokerError::Issuer(format!("rpc request failed: {e}")))?
            .json()
            .await
            .map_err(|e| BrokerError::Issuer(format!("rpc response parse failed: {e}")))?;
        if let Some(error) = resp.get("error") {
            return Err(BrokerError::Issuer(format!("rpc error: {error}")));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| BrokerError::Issuer("rpc response missing result".into()))
    }

    /// Contract code at an address (`eth_getCode`), used to verify deployments.
    pub async fn code_at(&self, address: &str) -> Result<String, BrokerError> {
        let result = self.call("eth_getCode", json!([address, "latest"])).await?;
        result
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| BrokerError::Issuer("eth_getCode returned a non-string".into()))
    }

    pub async fn chain_id(&self) -> Result<u64, BrokerError> {
        parse_hex_u64(self.call("eth_chainId", json!([])).await?)
    }

    /// `eth_getLogs` restricted to one address and topic filter (used to prove on-chain
    /// anchoring without trusting any indexer).
    pub async fn get_logs(
        &self,
        address: &str,
        topics: Vec<Value>,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Value>, BrokerError> {
        let filter = json!({
            "address": address,
            "topics": topics,
            "fromBlock": format!("0x{from_block:x}"),
            "toBlock": format!("0x{to_block:x}"),
        });
        let result = self.call("eth_getLogs", json!([filter])).await?;
        Ok(result.as_array().cloned().unwrap_or_default())
    }

    pub async fn block_number(&self) -> Result<u64, BrokerError> {
        parse_hex_u64(self.call("eth_blockNumber", json!([])).await?)
    }

    pub async fn nonce(&self, address: &str) -> Result<u64, BrokerError> {
        parse_hex_u64(
            self.call("eth_getTransactionCount", json!([address, "pending"]))
                .await?,
        )
    }

    pub async fn gas_price(&self) -> Result<u128, BrokerError> {
        parse_hex_u128(self.call("eth_gasPrice", json!([])).await?)
    }

    pub async fn max_priority_fee(&self) -> Option<u128> {
        let result = self
            .call("eth_maxPriorityFeePerGas", json!([]))
            .await
            .ok()?;
        parse_hex_u128(result).ok()
    }

    pub async fn estimate_gas(&self, from: &str, to: &str, data: &str) -> Result<u64, BrokerError> {
        let result = self
            .call(
                "eth_estimateGas",
                json!([{ "from": from, "to": to, "data": data, "value": "0x0" }]),
            )
            .await?;
        parse_hex_u64(result)
    }

    pub async fn send_raw_transaction(&self, raw: &str) -> Result<String, BrokerError> {
        let result = self.call("eth_sendRawTransaction", json!([raw])).await?;
        result
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| BrokerError::Issuer("sendRawTransaction returned no hash".into()))
    }

    /// Read-only `eth_call`; returns the raw hex result.
    pub async fn eth_call(&self, to: &str, data: &str) -> Result<String, BrokerError> {
        let result = self
            .call(
                "eth_call",
                json!([{ "to": to, "data": data, "value": "0x0" }, "latest"]),
            )
            .await?;
        result
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| BrokerError::Issuer("eth_call returned no data".into()))
    }

    /// Deploy raw creation bytecode; returns (tx hash, predicted contract address).
    pub async fn deploy(
        &self,
        signer: &EthSigner,
        bytecode: &[u8],
        chain_id: u64,
    ) -> Result<(String, [u8; 20]), BrokerError> {
        let from = signer.address_hex();
        let nonce = self.nonce(&from).await?;
        let gas_price = self.gas_price().await.unwrap_or(1_000_000_000);
        let tx = TxEip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: gas_price.saturating_mul(2).max(2_000_000_000),
            gas_limit: 2_000_000,
            to: None,
            value: 0,
            data: bytecode.to_vec(),
        };
        let raw = signer.sign_eip1559(&tx).await?;
        let tx_hash = self.send_raw_transaction(&raw).await?;
        Ok((tx_hash, contract_address(&signer.address, nonce)))
    }

    pub async fn transaction_succeeded(&self, tx_hash: &str) -> Result<bool, BrokerError> {
        let receipt = self
            .call("eth_getTransactionReceipt", json!([tx_hash]))
            .await?;
        Ok(receipt
            .get("status")
            .and_then(|s| s.as_str())
            .map(|s| s == "0x1")
            .unwrap_or(false))
    }

    /// Returns `Some((success, block_number))` if the tx is mined, `None` if still pending.
    pub async fn transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> Result<Option<(bool, Option<u64>)>, BrokerError> {
        let receipt = self
            .call("eth_getTransactionReceipt", json!([tx_hash]))
            .await?;
        if receipt.is_null() {
            return Ok(None);
        }
        let success = receipt
            .get("status")
            .and_then(|s| s.as_str())
            .map(|s| s == "0x1")
            .unwrap_or(false);
        let block = receipt
            .get("blockNumber")
            .and_then(|b| b.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        Ok(Some((success, block)))
    }
}

fn contract_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let encoded = Rlp::List(vec![
        Rlp::Bytes(sender),
        Rlp::Bytes(&minimal_be(nonce as u128)),
    ])
    .encode();
    let hash = keccak(&encoded);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

fn parse_hex_u64(value: Value) -> Result<u64, BrokerError> {
    let s = value
        .as_str()
        .ok_or_else(|| BrokerError::Issuer("expected hex string".into()))?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|e| BrokerError::Issuer(format!("bad hex u64 '{s}': {e}")))
}

fn parse_hex_u64_opt(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

fn parse_hex_u128(value: Value) -> Result<u128, BrokerError> {
    let s = value
        .as_str()
        .ok_or_else(|| BrokerError::Issuer("expected hex string".into()))?;
    u128::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|e| BrokerError::Issuer(format!("bad hex u128 '{s}': {e}")))
}

// ── Anchor submitter ────────────────────────────────────────────────────────

/// Canonical `Anchored(bytes32,uint256,bytes32,uint64,uint64)` event signature.
pub const ANCHOR_EVENT_SIGNATURE: &str = "Anchored(bytes32,uint256,bytes32,uint64,uint64)";

/// Evidence that a root is recorded on-chain.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OnchainAnchorClaim {
    pub block_number: u64,
    pub confirmations: u64,
    pub batch_index: Option<u64>,
}

pub struct AnchorSubmitter {
    rpc: RpcClient,
    signer: EthSigner,
    contract: [u8; 20],
    chain_id: u64,
    /// Refuse to submit when the computed fee exceeds this cap (None = no cap).
    max_fee_per_gas: Option<u128>,
}

impl AnchorSubmitter {
    pub fn new(rpc_url: &str, private_key: &str, contract: &str) -> Result<Self, BrokerError> {
        Self::with_backend(
            rpc_url,
            Arc::new(LocalSigner::from_hex(private_key)?),
            contract,
        )
    }

    /// Build from a signing backend (local key or KMS/HSM bridge).
    pub fn with_backend(
        rpc_url: &str,
        backend: Arc<dyn DigestSigner>,
        contract: &str,
    ) -> Result<Self, BrokerError> {
        Ok(Self {
            rpc: RpcClient::new(rpc_url),
            signer: EthSigner::from_backend(backend)?,
            contract: parse_address(contract)?,
            chain_id: 0, // resolved lazily
            max_fee_per_gas: crate::config::anchor_max_fee_per_gas(),
        })
    }

    /// The configured fee ceiling, when any.
    pub fn max_fee_per_gas(&self) -> Option<u128> {
        self.max_fee_per_gas
    }

    /// Override the fee ceiling (used by tests; production reads the environment).
    pub fn with_max_fee_per_gas(mut self, cap: Option<u128>) -> Self {
        self.max_fee_per_gas = cap;
        self
    }

    pub fn signer_address(&self) -> String {
        self.signer.address_hex()
    }

    /// Rebind to a different RPC/contract, reusing the same signing backend and fee cap.
    pub fn rebind(&self, rpc_url: &str, contract: &str) -> Result<Self, BrokerError> {
        Ok(
            Self::with_backend(rpc_url, self.signer.backend(), contract)?
                .with_max_fee_per_gas(self.max_fee_per_gas),
        )
    }

    /// The configured chain id (0 = resolved from the node on submit).
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The RPC endpoint this submitter talks to.
    pub fn rpc_url(&self) -> &str {
        self.rpc.url()
    }

    pub fn contract_hex(&self) -> String {
        format!("0x{}", hex::encode(self.contract))
    }

    /// Submit `anchor(bytes32 tenant, bytes32 root, uint64 count)`; returns the tx hash.
    /// Look for the `Anchored` event carrying `root` for `tenant` within `lookback` blocks.
    /// Proves the root exists on-chain without trusting the broker's own records.
    pub async fn verify_anchored(
        &self,
        tenant: [u8; 32],
        root: [u8; 32],
        lookback: u64,
    ) -> Result<Option<OnchainAnchorClaim>, BrokerError> {
        let topic0 = format!(
            "0x{}",
            hex::encode(crate::merkle::keccak(ANCHOR_EVENT_SIGNATURE.as_bytes()))
        );
        let topic1 = format!("0x{}", hex::encode(tenant));
        let head = self.rpc.block_number().await?;
        let from = head.saturating_sub(lookback);
        let logs = self
            .rpc
            .get_logs(
                &self.contract_hex(),
                vec![json!(topic0), json!(topic1)],
                from,
                head,
            )
            .await?;

        for log in logs {
            let Some(data) = log.get("data").and_then(|v| v.as_str()) else {
                continue;
            };
            let Ok(bytes) = hex::decode(data.trim_start_matches("0x")) else {
                continue;
            };
            // First non-indexed word is `merkleRoot`.
            if bytes.len() < 32 || bytes[..32] != root {
                continue;
            }
            let block_number = log
                .get("blockNumber")
                .and_then(|v| v.as_str())
                .and_then(parse_hex_u64_opt)
                .unwrap_or(head);
            let batch_index = log
                .get("topics")
                .and_then(|v| v.as_array())
                .and_then(|topics| topics.get(2))
                .and_then(|topic| topic.as_str())
                .and_then(parse_hex_u64_opt);
            return Ok(Some(OnchainAnchorClaim {
                block_number,
                confirmations: head.saturating_sub(block_number) + 1,
                batch_index,
            }));
        }
        Ok(None)
    }

    pub async fn submit(
        &self,
        tenant: [u8; 32],
        root: [u8; 32],
        count: u64,
    ) -> Result<String, BrokerError> {
        let calldata = crate::merkle::anchor_calldata(tenant, root, count);
        let data = hex::decode(calldata.trim_start_matches("0x"))
            .map_err(|e| BrokerError::Internal(format!("bad calldata: {e}")))?;

        let chain_id = if self.chain_id != 0 {
            self.chain_id
        } else {
            self.rpc.chain_id().await?
        };
        let from = self.signer.address_hex();
        let to = format!("0x{}", hex::encode(self.contract));

        let gas_limit = match self.rpc.estimate_gas(&from, &to, &calldata).await {
            Ok(gas) => gas + gas / 5,
            Err(_) => 250_000,
        };
        let gas_price = self.rpc.gas_price().await.unwrap_or(1_000_000_000);
        let priority = self.rpc.max_priority_fee().await.unwrap_or(1_000_000_000);
        let max_fee = gas_price.saturating_mul(2).max(priority);

        // Fee ceiling: refuse to submit when the network's fee would exceed the configured
        // cap, instead of paying whatever the chain asks (misconfigured chain / fee spike).
        if let Some(cap) = self.max_fee_per_gas {
            if max_fee > cap {
                return Err(BrokerError::Issuer(format!(
                    "gas fee {max_fee} wei exceeds the configured cap {cap} wei; refusing to submit"
                )));
            }
        }

        let tx = TxEip1559 {
            chain_id,
            nonce: self.rpc.nonce(&from).await?,
            max_priority_fee_per_gas: priority,
            max_fee_per_gas: max_fee,
            gas_limit,
            to: Some(self.contract),
            value: 0,
            data,
        };
        let raw = self.signer.sign_eip1559(&tx).await?;
        self.rpc.send_raw_transaction(&raw).await
    }

    pub async fn wait_for_success(
        &self,
        tx_hash: &str,
        attempts: u32,
    ) -> Result<bool, BrokerError> {
        for _ in 0..attempts {
            if self
                .rpc
                .transaction_succeeded(tx_hash)
                .await
                .unwrap_or(false)
            {
                return Ok(true);
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        Ok(false)
    }

    /// One-shot observation of a tx: `Some((success, block))` when mined, `None` if pending.
    pub async fn observe(&self, tx_hash: &str) -> Result<Option<(bool, u64)>, BrokerError> {
        Ok(self
            .rpc
            .transaction_receipt(tx_hash)
            .await?
            .map(|(success, block)| (success, block.unwrap_or(0))))
    }

    /// Current canonical head block.
    pub async fn head_block(&self) -> Result<u64, BrokerError> {
        self.rpc.block_number().await
    }

    /// Poll for a mined receipt. Returns `Some((success, block))` when mined, `None` on timeout.
    pub async fn confirm(
        &self,
        tx_hash: &str,
        attempts: u32,
    ) -> Result<Option<(bool, u64)>, BrokerError> {
        for _ in 0..attempts {
            match self.rpc.transaction_receipt(tx_hash).await {
                Ok(Some((success, block))) => return Ok(Some((success, block.unwrap_or(0)))),
                Ok(None) => {}
                Err(e) => return Err(e),
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        Ok(None)
    }
}

fn parse_address(s: &str) -> Result<[u8; 20], BrokerError> {
    let raw = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| BrokerError::Invalid(format!("bad address: {e}")))?;
    if raw.len() != 20 {
        return Err(BrokerError::Invalid(format!(
            "expected 20 bytes, got {}",
            raw.len()
        )));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&raw);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlp_known_vectors() {
        assert_eq!(Rlp::Bytes(b"").encode(), vec![0x80]);
        assert_eq!(
            Rlp::Bytes(b"dog").encode(),
            hex::decode("83646f67").unwrap()
        );
        assert_eq!(Rlp::Bytes(&[0x00]).encode(), vec![0x00]);
        assert_eq!(Rlp::Bytes(&[0x0f]).encode(), vec![0x0f]);
        let list = Rlp::List(vec![Rlp::Bytes(b"cat"), Rlp::Bytes(b"dog")]).encode();
        assert_eq!(list, hex::decode("c88363617483646f67").unwrap());
    }

    #[test]
    fn minimal_be_strips_zeros() {
        assert_eq!(minimal_be(0), Vec::<u8>::new());
        assert_eq!(minimal_be(1), vec![1]);
        assert_eq!(minimal_be(0x0100), vec![1, 0]);
    }

    #[tokio::test]
    async fn signs_typed_transaction() {
        let signer = EthSigner::from_hex(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap();
        assert_eq!(
            signer.address_hex(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );

        let tx = TxEip1559 {
            chain_id: 31337,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21000,
            to: Some([0x11; 20]),
            value: 0,
            data: vec![],
        };
        let raw = signer.sign_eip1559(&tx).await.unwrap();
        assert!(raw.starts_with("0x02"));
        // deterministic
        assert_eq!(raw, signer.sign_eip1559(&tx).await.unwrap());
    }

    #[test]
    fn rlp_integer_encoding() {
        assert_eq!(rlp_u128(0), vec![0x80]);
        assert_eq!(rlp_u128(15), vec![0x0f]);
        assert_eq!(rlp_u128(1024), vec![0x82, 0x04, 0x00]);
        assert_eq!(rlp_bytes(&[1, 2, 3]), vec![0x83, 1, 2, 3]);
    }
}
