//! AWS STS issuer — `AssumeRole` with an inline session policy (SigV4 signed).
//!
//! Note: STS `AssumeRole` enforces a 900-second minimum duration, so the issued
//! credential cannot be shorter than 15 minutes even though the logical grant is scoped
//! to a single action.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{
    new_reference, CredentialMaterial, EphemeralCredential, IssueRequest, Issuer, RevokeEffect,
};
use crate::config::AwsConfig;
use crate::error::BrokerError;

type HmacSha256 = Hmac<Sha256>;

struct Issued {
    tenant: String,
    session_name: String,
}

pub struct AwsStsIssuer {
    cfg: AwsConfig,
    client: reqwest::Client,
    /// reference -> (tenant, session name) so a credential can be revoked natively by
    /// attaching a deny policy scoped to `sts:RoleSessionName`.
    issued: Arc<Mutex<HashMap<String, Issued>>>,
}

impl AwsStsIssuer {
    pub fn new(cfg: AwsConfig) -> Self {
        Self {
            cfg,
            client: crate::netguard::outbound_client(),
            issued: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn iam_endpoint(&self) -> String {
        self.cfg
            .iam_endpoint_override
            .clone()
            .unwrap_or_else(|| "https://iam.amazonaws.com".to_string())
    }

    fn role_name(&self) -> Option<String> {
        self.cfg.role_arn.rsplit('/').next().map(str::to_string)
    }

    fn host(&self) -> String {
        let endpoint = self.endpoint();
        endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string()
    }

    fn endpoint(&self) -> String {
        self.cfg
            .endpoint_override
            .clone()
            .unwrap_or_else(|| format!("https://sts.{}.amazonaws.com", self.cfg.region))
    }
}

#[async_trait]
impl Issuer for AwsStsIssuer {
    fn provider(&self) -> &'static str {
        "aws"
    }

    async fn issue(&self, req: &IssueRequest) -> Result<EphemeralCredential, BrokerError> {
        let duration = clamp_duration(req.ttl_seconds);
        let policy = session_policy(req);
        let session_name =
            sanitize_session_name(&format!("{}-{}", self.cfg.session_name, req.agent_id));
        let reference = new_reference(self.provider());

        let params = vec![
            ("Action".to_string(), "AssumeRole".to_string()),
            ("Version".to_string(), "2011-06-15".to_string()),
            ("RoleArn".to_string(), self.cfg.role_arn.clone()),
            ("RoleSessionName".to_string(), session_name.clone()),
            ("DurationSeconds".to_string(), duration.to_string()),
            ("Policy".to_string(), policy),
        ];
        let body = form_encode(&params);

        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let host = self.host();
        let content_type = "application/x-www-form-urlencoded; charset=utf-8";

        let authorization = sign_v4(SignV4Input {
            method: "POST",
            path: "/",
            host: &host,
            content_type,
            body: &body,
            amz_date: &amz_date,
            date_stamp: &date_stamp,
            region: &self.cfg.region,
            service: "sts",
            access_key_id: &self.cfg.access_key_id,
            secret_access_key: &self.cfg.secret_access_key,
            session_token: self.cfg.session_token.as_deref(),
        });

        let mut request = self
            .client
            .post(self.endpoint())
            .header("content-type", content_type)
            .header("x-amz-date", &amz_date)
            .header("authorization", authorization);
        if let Some(token) = &self.cfg.session_token {
            request = request.header("x-amz-security-token", token);
        }

        let resp = request
            .body(body)
            .send()
            .await
            .map_err(|e| BrokerError::Issuer(format!("sts request failed: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| BrokerError::Issuer(format!("sts body read failed: {e}")))?;
        if !status.is_success() {
            return Err(BrokerError::Issuer(format!(
                "sts returned {status}: {}",
                truncate(&text, 300)
            )));
        }

        let access_key_id = extract(&text, "AccessKeyId")
            .ok_or_else(|| BrokerError::Issuer("sts response missing AccessKeyId".into()))?;
        let secret_access_key = extract(&text, "SecretAccessKey")
            .ok_or_else(|| BrokerError::Issuer("sts response missing SecretAccessKey".into()))?;
        let session_token = extract(&text, "SessionToken")
            .ok_or_else(|| BrokerError::Issuer("sts response missing SessionToken".into()))?;
        let expiration = extract(&text, "Expiration").unwrap_or_default();

        if let Ok(mut issued) = self.issued.lock() {
            issued.insert(
                reference.clone(),
                Issued {
                    tenant: req.tenant.clone(),
                    session_name,
                },
            );
        }

        Ok(EphemeralCredential {
            provider: self.provider().to_string(),
            resource: req.resource.clone(),
            ttl_seconds: duration,
            single_use: false,
            args_hash: req.args_hash.clone(),
            material: CredentialMaterial::AwsSts {
                access_key_id,
                secret_access_key,
                session_token,
                expiration,
            },
            reference: Some(reference),
            issuance_id: None,
        })
    }

    /// Revoke an issued STS session by attaching an inline deny policy to the role that
    /// denies all actions when `sts:RoleSessionName` matches the issued session.
    async fn revoke_credential(
        &self,
        tenant: &str,
        reference: &str,
    ) -> Result<RevokeEffect, BrokerError> {
        let session_name = match self.issued.lock().ok().and_then(|m| {
            m.get(reference)
                .filter(|i| i.tenant == tenant)
                .map(|i| i.session_name.clone())
        }) {
            Some(name) => name,
            None => return Ok(RevokeEffect::NotFound),
        };

        let role_name = self
            .role_name()
            .ok_or_else(|| BrokerError::Issuer("cannot derive role name from ARN".into()))?;

        let deny = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": { "StringEquals": { "sts:RoleSessionName": session_name } }
            }]
        })
        .to_string();
        let policy_name = format!(
            "tessera-revoke-{}",
            session_name.replace(['=', ',', '.', '@'], "-")
        );

        let params = vec![
            ("Action".to_string(), "PutRolePolicy".to_string()),
            ("Version".to_string(), "2010-05-08".to_string()),
            ("RoleName".to_string(), role_name),
            ("PolicyName".to_string(), policy_name),
            ("PolicyDocument".to_string(), deny),
        ];
        let body = form_encode(&params);

        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let host = self
            .iam_endpoint()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        let content_type = "application/x-www-form-urlencoded; charset=utf-8";

        let authorization = sign_v4(SignV4Input {
            method: "POST",
            path: "/",
            host: &host,
            content_type,
            body: &body,
            amz_date: &amz_date,
            date_stamp: &date_stamp,
            region: "us-east-1", // IAM is global
            service: "iam",
            access_key_id: &self.cfg.access_key_id,
            secret_access_key: &self.cfg.secret_access_key,
            session_token: self.cfg.session_token.as_deref(),
        });

        let mut request = self
            .client
            .post(self.iam_endpoint())
            .header("content-type", content_type)
            .header("x-amz-date", &amz_date)
            .header("authorization", authorization);
        if let Some(token) = &self.cfg.session_token {
            request = request.header("x-amz-security-token", token);
        }

        let resp = request
            .body(body)
            .send()
            .await
            .map_err(|e| BrokerError::Issuer(format!("iam request failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(BrokerError::Issuer(format!(
                "iam PutRolePolicy returned {}",
                resp.status()
            )));
        }

        if let Ok(mut issued) = self.issued.lock() {
            issued.remove(reference);
        }
        Ok(RevokeEffect::Revoked)
    }
}

/// STS AssumeRole duration bounds: 900s minimum, 43200s maximum.
pub fn clamp_duration(requested: u32) -> u32 {
    requested.clamp(900, 43_200)
}

/// Inline session policy restricting the temporary credential to the requested action/ARN.
pub fn session_policy(req: &IssueRequest) -> String {
    let action = req.scope.first().cloned().unwrap_or_else(|| {
        req.resource
            .split_once(':')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_else(|| "*".to_string())
    });
    let arn = req
        .args
        .get("resource_arn")
        .and_then(|v| v.as_str())
        .unwrap_or("*");
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [action],
            "Resource": [arn]
        }]
    })
    .to_string()
}

struct SignV4Input<'a> {
    method: &'a str,
    path: &'a str,
    host: &'a str,
    content_type: &'a str,
    body: &'a str,
    amz_date: &'a str,
    date_stamp: &'a str,
    region: &'a str,
    service: &'a str,
    access_key_id: &'a str,
    secret_access_key: &'a str,
    session_token: Option<&'a str>,
}

fn sign_v4(i: SignV4Input<'_>) -> String {
    let mut canonical_headers = format!(
        "content-type:{}\nhost:{}\nx-amz-date:{}\n",
        i.content_type, i.host, i.amz_date
    );
    let mut signed_headers = "content-type;host;x-amz-date".to_string();
    if let Some(token) = i.session_token {
        canonical_headers.push_str(&format!("x-amz-security-token:{token}\n"));
        signed_headers.push_str(";x-amz-security-token");
    }

    let payload_hash = sha256_hex(i.body.as_bytes());
    let canonical_request = format!(
        "{}\n{}\n\n{}\n{}\n{}",
        i.method, i.path, canonical_headers, signed_headers, payload_hash
    );

    let scope = format!("{}/{}/{}/aws4_request", i.date_stamp, i.region, i.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        i.amz_date,
        scope,
        sha256_hex(canonical_request.as_bytes())
    );

    let key = signing_key(i.secret_access_key, i.date_stamp, i.region, i.service);
    let signature = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        i.access_key_id, scope, signed_headers, signature
    )
}

fn signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn form_encode(params: &[(String, String)]) -> String {
    let mut sorted = params.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&")
}

/// AWS SigV4 percent-encoding.
pub fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::new();
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn sanitize_session_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '=' | ',' | '.' | '@' | '-' | '_'))
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "tessera-agent".to_string()
    } else {
        cleaned
    }
}

fn extract(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

fn truncate(s: &str, n: usize) -> &str {
    if s.len() <= n {
        s
    } else {
        &s[..n]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(resource: &str, args: serde_json::Value) -> IssueRequest {
        IssueRequest {
            tenant: "t".into(),
            agent_id: "agent-1".into(),
            user_id: "u".into(),
            resource: resource.into(),
            scope: vec![],
            ttl_seconds: 30,
            args_hash: "0x00".into(),
            args,
        }
    }

    #[test]
    fn duration_clamped_to_sts_minimum() {
        assert_eq!(clamp_duration(30), 900);
        assert_eq!(clamp_duration(900), 900);
        assert_eq!(clamp_duration(999_999), 43_200);
    }

    #[test]
    fn session_policy_restricts_action_and_arn() {
        let p = session_policy(&req(
            "aws:s3:GetObject",
            serde_json::json!({"resource_arn": "arn:aws:s3:::reports/x"}),
        ));
        assert!(p.contains("\"s3:GetObject\""));
        assert!(p.contains("arn:aws:s3:::reports/x"));
    }

    #[test]
    fn uri_encode_matches_sigv4_rules() {
        assert_eq!(uri_encode("a b/c", true), "a%20b%2Fc");
        assert_eq!(uri_encode("a b/c", false), "a%20b/c");
        assert_eq!(uri_encode("A-Za-z0-9_.~", true), "A-Za-z0-9_.~");
    }

    #[test]
    fn authorization_header_shape() {
        let auth = sign_v4(SignV4Input {
            method: "POST",
            path: "/",
            host: "sts.us-east-1.amazonaws.com",
            content_type: "application/x-www-form-urlencoded; charset=utf-8",
            body: "Action=AssumeRole&Version=2011-06-15",
            amz_date: "20260915T120000Z",
            date_stamp: "20260915",
            region: "us-east-1",
            service: "sts",
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            session_token: None,
        });
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260915/us-east-1/sts/aws4_request"
        ));
        assert!(auth.contains("SignedHeaders=content-type;host;x-amz-date"));
        assert_eq!(auth.matches("Signature=").count(), 1);
    }

    #[test]
    fn signature_is_deterministic() {
        let make = || {
            sign_v4(SignV4Input {
                method: "POST",
                path: "/",
                host: "sts.us-east-1.amazonaws.com",
                content_type: "application/x-www-form-urlencoded; charset=utf-8",
                body: "Action=AssumeRole",
                amz_date: "20260915T120000Z",
                date_stamp: "20260915",
                region: "us-east-1",
                service: "sts",
                access_key_id: "AKIDEXAMPLE",
                secret_access_key: "secret",
                session_token: None,
            })
        };
        assert_eq!(make(), make());
    }
}
