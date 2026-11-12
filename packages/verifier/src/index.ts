import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import {
  AnyReceipt,
  isReceiptV2,
  payloadHash,
  validateReceipt,
} from "@tessera/receipt-schema";

export interface VerifyDomain {
  chainId: number | bigint;
  verifyingContract: string;
}

export interface VerifyReceiptResult {
  valid: boolean;
  recovered?: string;
  payloadHash: string;
  matchesExpected?: boolean;
  errors: string[];
}

export interface ChainEntry {
  payloadHash?: string;
  payload_hash?: string;
  receipt: AnyReceipt;
}

export interface VerifyChainResult {
  valid: boolean;
  length: number;
  recovered?: string;
  errors: string[];
}

const RECEIPT_TYPEHASH = keccak_256(
  utf8ToBytes("Receipt(bytes32 payloadHash,bytes32 prev,bytes32 agentIdHash,bytes32 nonce)"),
);
const DOMAIN_TYPEHASH = keccak_256(
  utf8ToBytes(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
  ),
);
const NAME_HASH = keccak_256(utf8ToBytes("TesseraReceipt"));

function strip0x(value: string): string {
  return value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
}

function u256(value: bigint): Uint8Array {
  if (value < 0n || value >= 1n << 256n) throw new Error("chainId out of range");
  const out = new Uint8Array(32);
  let remaining = value;
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

function addressWord(address: string): Uint8Array {
  const raw = hexToBytes(strip0x(address));
  if (raw.length !== 20) throw new Error("verifyingContract must be a 20-byte address");
  const out = new Uint8Array(32);
  out.set(raw, 12);
  return out;
}

function bytes32(value: string, field: string): Uint8Array {
  const raw = hexToBytes(strip0x(value));
  if (raw.length !== 32) throw new Error(`${field} must be a 32-byte hex value`);
  return raw;
}

export function domainForReceipt(receipt: AnyReceipt): string {
  return receipt.v >= 2 ? "2" : "1";
}

export function domainSeparator(domain: VerifyDomain, version: string): Uint8Array {
  return keccak_256(
    concatBytes(
      DOMAIN_TYPEHASH,
      NAME_HASH,
      keccak_256(utf8ToBytes(version)),
      u256(BigInt(domain.chainId)),
      addressWord(domain.verifyingContract),
    ),
  );
}

export function eip712Digest(receipt: AnyReceipt, domain: VerifyDomain): Uint8Array {
  const payload = bytes32(payloadHash(receipt), "payloadHash");
  const prev = receipt.prev ? bytes32(receipt.prev, "prev") : new Uint8Array(32);
  const agentIdHash = keccak_256(utf8ToBytes(receipt.agent));
  const nonce = bytes32(receipt.nonce, "nonce");
  const structHash = keccak_256(
    concatBytes(RECEIPT_TYPEHASH, payload, prev, agentIdHash, nonce),
  );
  return keccak_256(
    concatBytes(
      Uint8Array.from([0x19, 0x01]),
      domainSeparator(domain, domainForReceipt(receipt)),
      structHash,
    ),
  );
}

export function recoverSigner(receipt: AnyReceipt, domain: VerifyDomain): string {
  if (!receipt.signature) throw new Error("receipt is unsigned");
  const raw = hexToBytes(strip0x(receipt.signature));
  if (raw.length !== 65) throw new Error("signature must be 65 bytes");
  const compact = raw.slice(0, 64);
  const v = raw[64] ?? 0;
  const recovery = v >= 27 ? v - 27 : v;
  if (recovery !== 0 && recovery !== 1) throw new Error("invalid recovery id");
  const parsed = secp256k1.Signature.fromCompact(compact);
  if (parsed.hasHighS()) throw new Error("signature is not low-S (malleable)");
  const signature = parsed.addRecoveryBit(recovery);
  const publicKey = signature.recoverPublicKey(eip712Digest(receipt, domain)).toRawBytes(false);
  const address = keccak_256(publicKey.slice(1)).slice(12);
  return `0x${bytesToHex(address)}`;
}

export function verifyReceipt(
  receipt: AnyReceipt,
  domain: VerifyDomain,
  expectedSigner?: string,
): VerifyReceiptResult {
  const errors = validateReceipt(receipt);
  const hash = payloadHash(receipt);
  if (!receipt.signature) errors.push("receipt is unsigned");
  let recovered: string | undefined;
  if (receipt.signature) {
    try {
      recovered = recoverSigner(receipt, domain);
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  const matchesExpected =
    expectedSigner && recovered
      ? recovered.toLowerCase() === expectedSigner.toLowerCase()
      : undefined;
  return {
    valid: errors.length === 0,
    ...(recovered ? { recovered } : {}),
    payloadHash: hash,
    ...(matchesExpected === undefined ? {} : { matchesExpected }),
    errors,
  };
}

export function verifyChain(
  entries: ChainEntry[],
  domain: VerifyDomain,
  expectedSigner?: string,
): VerifyChainResult {
  const errors: string[] = [];
  if (entries.length === 0) errors.push("chain is empty");
  let previous: string | null = null;
  let recovered: string | undefined;
  for (const [index, entry] of entries.entries()) {
    const receipt = entry.receipt;
    const result = verifyReceipt(receipt, domain, expectedSigner);
    for (const error of result.errors) errors.push(`entry ${index}: ${error}`);
    const stored = entry.payloadHash ?? entry.payload_hash;
    if (stored && stored.toLowerCase() !== result.payloadHash.toLowerCase()) {
      errors.push(`entry ${index}: payload hash does not match the receipt`);
    }
    if (result.recovered) {
      if (!recovered) recovered = result.recovered;
      else if (recovered.toLowerCase() !== result.recovered.toLowerCase()) {
        errors.push("chain contains more than one signer");
      }
    }
    const prev = receipt.prev ?? null;
    if (prev !== previous) errors.push(`entry ${index}: prev link does not match`);
    previous = result.payloadHash;
  }
  if (expectedSigner && recovered && recovered.toLowerCase() !== expectedSigner.toLowerCase()) {
    errors.push("recovered signer does not match expectedSigner");
  }
  return { valid: errors.length === 0, length: entries.length, ...(recovered ? { recovered } : {}), errors };
}

/**
 * Verify an authorization record and its outcome record. The outcome must link to the
 * authorization via `prev` (immediate) or `authorizationReceiptId` (late), and share the
 * same `actionId`.
 */
export function verifyAction(
  authorization: AnyReceipt,
  outcome: AnyReceipt,
  domain: VerifyDomain,
  expectedSigner?: string,
): VerifyChainResult {
  const errors: string[] = [];
  const auth = verifyReceipt(authorization, domain, expectedSigner);
  const out = verifyReceipt(outcome, domain, expectedSigner);
  errors.push(...auth.errors.map((e) => `authorization: ${e}`));
  errors.push(...out.errors.map((e) => `outcome: ${e}`));
  const authActionId = isReceiptV2(authorization) ? authorization.actionId : undefined;
  const outcomeActionId = isReceiptV2(outcome) ? outcome.actionId : undefined;
  if (authActionId && outcomeActionId && authActionId !== outcomeActionId) {
    errors.push("actionId mismatch between authorization and outcome");
  }
  const linkedByPrev = outcome.prev === auth.payloadHash;
  const linkedById =
    isReceiptV2(outcome) && outcome.authorizationReceiptId === auth.payloadHash;
  if (!linkedByPrev && !linkedById) {
    errors.push("outcome does not link to authorization");
  }
  return {
    valid: errors.length === 0,
    length: 2,
    ...(auth.recovered ? { recovered: auth.recovered } : {}),
    errors,
  };
}
