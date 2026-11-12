//! Generic provider proxy for broker-held grants.
//!
//! When an issuer cannot hand the agent a native short-lived credential (e.g. Stripe),
//! it stores the real secret and returns a grant id. The agent calls this proxy, the
//! broker redeems the grant (re-checking `args_hash`, expiry, single-use) and forwards
//! exactly one request to the provider using the stored [`ProxySpec`].

use serde::{Deserialize, Serialize};

use crate::error::BrokerError;
use crate::issuers::aws_sts::uri_encode;
use crate::issuers::ProxySpec;
use crate::receipt::GrantReceipt;

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyRequest {
    pub grant_id: String,
    /// Must match the hash bound to the grant at issuance.
    pub args_hash: String,
    pub method: String,
    /// Path relative to the provider base URL, e.g. `/v1/refunds`.
    pub path: String,
    #[serde(default)]
    pub query: Vec<(String, String)>,
    /// Defaults to `application/x-www-form-urlencoded` when a body is present.
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: String,
    /// Action shared by the authorization and the broker-observed outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    /// Authorization receipt the broker-observed outcome belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_receipt_id: Option<String>,
    /// Receipt id of the broker-observed outcome, when one was appended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_receipt_id: Option<String>,
    /// The signed outcome record, so the control plane can persist it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_receipt: Option<GrantReceipt>,
    /// True only when the broker appended the outcome receipt.
    #[serde(default)]
    pub outcome_recorded: bool,
}

/// Forward one request to the provider encoded by `spec`, authenticating with `secret`.
pub async fn forward(
    client: &reqwest::Client,
    spec: &ProxySpec,
    secret: &str,
    req: &ProxyRequest,
) -> Result<ProxyResponse, BrokerError> {
    if !req.path.starts_with('/') || req.path.contains("://") {
        return Err(BrokerError::Invalid("path must be a relative path".into()));
    }

    // Only ordinary HTTP methods may be forwarded (no CONNECT/TRACE/extension tokens).
    let method_str = req.method.to_uppercase();
    if !ALLOWED_METHODS.contains(&method_str.as_str()) {
        return Err(BrokerError::Invalid(format!(
            "method '{method_str}' is not allowed"
        )));
    }
    let method = reqwest::Method::from_bytes(method_str.as_bytes())
        .map_err(|e| BrokerError::Invalid(format!("bad method: {e}")))?;

    // Reject header-injection / oversized inputs before they reach the upstream request.
    if let Some(ct) = &req.content_type {
        if ct.contains(['\r', '\n']) || ct.len() > 128 {
            return Err(BrokerError::Invalid("invalid content-type".into()));
        }
    }
    if req.query.len() > 32
        || req
            .query
            .iter()
            .any(|(k, v)| k.len() > 256 || v.len() > 1024)
    {
        return Err(BrokerError::Invalid("query too large".into()));
    }

    let mut url = format!("{}{}", spec.base_url.trim_end_matches('/'), req.path);
    if !req.query.is_empty() {
        let qs = req
            .query
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
            .collect::<Vec<_>>()
            .join("&");
        url.push('?');
        url.push_str(&qs);
    }

    let auth_value = if spec.auth_scheme.is_empty() {
        secret.to_string()
    } else {
        format!("{} {}", spec.auth_scheme, secret)
    };

    let mut builder = client
        .request(method, &url)
        .header(&spec.auth_header, auth_value);

    if let Some(body) = &req.body {
        builder = builder.header(
            "content-type",
            req.content_type
                .clone()
                .unwrap_or_else(|| "application/x-www-form-urlencoded".to_string()),
        );
        builder = builder.body(body.clone());
    }

    let resp = builder
        .send()
        .await
        .map_err(|e| BrokerError::Issuer(format!("proxy request failed: {e}")))?;

    let status = resp.status().as_u16();
    if resp
        .content_length()
        .map(|len| len > MAX_RESPONSE_BYTES)
        .unwrap_or(false)
    {
        return Err(BrokerError::Issuer(format!(
            "provider response exceeds {MAX_RESPONSE_BYTES} bytes"
        )));
    }
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = resp
        .text()
        .await
        .map_err(|e| BrokerError::Issuer(format!("proxy body read failed: {e}")))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(BrokerError::Issuer(format!(
            "provider response exceeds {MAX_RESPONSE_BYTES} bytes"
        )));
    }

    Ok(ProxyResponse {
        status,
        content_type,
        body,
        action_id: None,
        authorization_receipt_id: None,
        outcome_receipt_id: None,
        outcome_receipt: None,
        outcome_recorded: false,
    })
}

/// Ordinary HTTP methods a brokered call may use.
const ALLOWED_METHODS: [&str; 6] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];
/// Upper bound on a forwarded provider response (guards broker memory).
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;

#[cfg(test)]
pub(crate) mod tests_support {
    use super::ProxyRequest;

    pub fn base_request() -> ProxyRequest {
        ProxyRequest {
            grant_id: "grant_stripe_x".into(),
            args_hash: "0x0".into(),
            method: "GET".into(),
            path: "/v1/refunds".into(),
            query: vec![],
            content_type: None,
            body: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_absolute_or_host_injecting_paths() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let client = reqwest::Client::new();
        let spec = ProxySpec {
            base_url: "https://api.stripe.com".into(),
            auth_header: "authorization".into(),
            auth_scheme: "Bearer".into(),
        };
        for bad in ["v1/refunds", "https://evil.example/x", "http://evil/x"] {
            let req = ProxyRequest {
                grant_id: "grant_stripe_x".into(),
                args_hash: "0x0".into(),
                method: "GET".into(),
                path: bad.into(),
                query: vec![],
                content_type: None,
                body: None,
            };
            let err = rt.block_on(forward(&client, &spec, "rk", &req));
            assert!(
                matches!(err, Err(BrokerError::Invalid(_))),
                "path {bad} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_disallowed_methods() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let client = reqwest::Client::new();
        let spec = ProxySpec {
            base_url: "https://api.stripe.com".into(),
            auth_header: "authorization".into(),
            auth_scheme: "Bearer".into(),
        };
        for bad in ["CONNECT", "TRACE", "OPTIONS"] {
            let req = ProxyRequest {
                grant_id: "grant_stripe_x".into(),
                args_hash: "0x0".into(),
                method: bad.into(),
                path: "/v1/refunds".into(),
                query: vec![],
                content_type: None,
                body: None,
            };
            let err = rt.block_on(forward(&client, &spec, "rk", &req));
            assert!(
                matches!(err, Err(BrokerError::Invalid(_))),
                "method {bad} should be rejected"
            );
        }
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::tests_support::*;
    use super::*;

    #[test]
    fn rejects_header_injection_and_oversized_query() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let client = reqwest::Client::new();
        let spec = ProxySpec {
            base_url: "https://api.stripe.com".into(),
            auth_header: "authorization".into(),
            auth_scheme: "Bearer".into(),
        };

        let mut req = base_request();
        req.content_type = Some("application/json\r\nX-Injected: 1".into());
        assert!(matches!(
            rt.block_on(forward(&client, &spec, "rk", &req)),
            Err(BrokerError::Invalid(_))
        ));

        let mut req = base_request();
        req.query = vec![("k".into(), "v".repeat(2048))];
        assert!(matches!(
            rt.block_on(forward(&client, &spec, "rk", &req)),
            Err(BrokerError::Invalid(_))
        ));
    }
}
