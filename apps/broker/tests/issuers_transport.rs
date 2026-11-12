//! Transport-level issuer tests: assert the exact HTTP requests that AWS STS and GitHub
//! issuers produce, against local mock servers (no live credentials, no network egress).

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use serde_json::{json, Value};

use tessera_broker::config::{AwsConfig, GithubConfig};
use tessera_broker::issuers::aws_sts::AwsStsIssuer;
use tessera_broker::issuers::github::GithubIssuer;
use tessera_broker::issuers::{CredentialMaterial, IssueRequest, Issuer, RevokeEffect};

/// Captured request: (headers, body).
type Recorded = Arc<Mutex<Option<(HeaderMap, String)>>>;

async fn spawn(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn request(resource: &str, args: Value) -> IssueRequest {
    IssueRequest {
        tenant: "t".into(),
        agent_id: "agent-1".into(),
        user_id: "user-1".into(),
        resource: resource.into(),
        scope: vec![],
        ttl_seconds: 30,
        args_hash: "0xargs".into(),
        args,
    }
}

const STS_XML: &str = r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIA_TEST</AccessKeyId>
      <SecretAccessKey>secret-test</SecretAccessKey>
      <SessionToken>token-test</SessionToken>
      <Expiration>2026-09-15T13:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#;

async fn sts_handler(
    State(recorded): State<Recorded>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, &'static str) {
    *recorded.lock().unwrap() = Some((headers, String::from_utf8_lossy(&body).to_string()));
    (StatusCode::OK, STS_XML)
}

#[tokio::test]
async fn aws_sts_request_is_sigv4_signed_and_parsed() {
    let recorded: Recorded = Arc::new(Mutex::new(None));
    let app = Router::new()
        .route("/", post(sts_handler))
        .with_state(recorded.clone());
    let base = spawn(app).await;

    let issuer = AwsStsIssuer::new(AwsConfig {
        region: "us-east-1".into(),
        role_arn: "arn:aws:iam::123456789012:role/tessera-agent".into(),
        session_name: "tessera-agent".into(),
        access_key_id: "AKIDEXAMPLE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
        endpoint_override: Some(base),
        iam_endpoint_override: None,
    });

    let credential = issuer
        .issue(&request(
            "aws:s3:GetObject",
            json!({"resource_arn": "arn:aws:s3:::reports/x"}),
        ))
        .await
        .unwrap();

    match credential.material {
        CredentialMaterial::AwsSts {
            access_key_id,
            secret_access_key,
            session_token,
            expiration,
        } => {
            assert_eq!(access_key_id, "ASIA_TEST");
            assert_eq!(secret_access_key, "secret-test");
            assert_eq!(session_token, "token-test");
            assert_eq!(expiration, "2026-09-15T13:00:00Z");
        }
        other => panic!("expected aws_sts material, got {other:?}"),
    }

    let (headers, body) = recorded.lock().unwrap().clone().unwrap();
    let auth = headers.get("authorization").unwrap().to_str().unwrap();
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
    assert!(auth.contains("/us-east-1/sts/aws4_request"));
    assert!(auth.contains("SignedHeaders=content-type;host;x-amz-date"));
    assert_eq!(auth.matches("Signature=").count(), 1);
    assert!(headers.get("x-amz-date").is_some());
    assert!(body.contains("Action=AssumeRole"));
    assert!(body.contains("DurationSeconds=900"));
    assert!(body.contains("Policy="));
    assert!(body.contains("reports"));
}

async fn github_handler(State(recorded): State<Recorded>, headers: HeaderMap) -> Json<Value> {
    *recorded.lock().unwrap() = Some((headers, String::new()));
    Json(json!({ "token": "ghs_test", "expires_at": "2026-09-15T13:00:00Z" }))
}

async fn github_revoke_handler() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Throwaway RSA key generated only for tests.
const TEST_RSA_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAIA6Ta+88/G0Q\n2BKbLhrG0wx+MrpLHqm3CQpDqCu7vnyi5hFPBMoyraiUtCmUY+Mrpm563VUEpvMK\nRPa+dJp9FmnW4jF3KWLivsUdcZBG5+0ST1Si/vVzUPHlAUU39mo8yBdOK5K2cULW\nTY0iZHu/5qSdMw2JIohF5X9TP/Aah2E5LPHt1OxTcBgwkK0HOo45plE8Kf1thACw\npPlP4Qx/p+vID1X+dfZ7zL3ZU5vC9NmQsQglH9caCq6WDbqjOQMz3m6jPy23n7Re\nNURUf4c8cI74tkJUNzv1Y+x+e16fksVnhsPdY6BJGSRTHNbUrMF8rxNscPqIkMLc\nGfzlf8hVAgMBAAECggEAIqrGJoi/0vfTcEok1VZ043J6mxzpK5vdUNczQHEMbySY\nlcZA0krRd2KJfEekBxAdEifGYKomaJ/9U9mM0mH07GRKdck71r4jhzmYFM+Ekp7P\n0tF4uq6ZuJSfCUz44fe3RL9wIR1QrFX0kvnMYSvTfpWOF4V6SEfwYfheyLVNTGPX\nn+lwVfVWd7IAGE92Pm/La6EPa5N0I1RA5T/qOFoaVXbmsJtEObtZcpNg5ZuF0mTd\nodARDT+1/t8Va/rgN/XsACGl7US6hf18kn964aebcAELn/+PGfwAPenuq+SIzpft\n9DRwcN9A+AtefSBOy7GPM9lr5I7TcbA/eBQgTHm1AQKBgQD6j7wXtE/rtxIymLfZ\nL23K17XSPheglbFGwGauynrXpdYoUMpo/kpW1OMZQ69eRAgszx7LQ3v7qqaAxA5E\nI5vKyiFpSJp3RZR4ECY4Ksc5Jxebhm+PCscMZk19rchQdb8NlWAC8CzcAuQ+Vj0q\neprupkf9ZTpczUv2olomdB/lgQKBgQDES53PbKuaRL8lEc+znzX3JRkH99Q3kdZL\nHFsCDFX86+P3Xfwz2B6nC+TnDjDg+/tRuMyoglQW3kg8WEZbMWK00Bks/l1ogelo\ntKBihni7t8uhED/bfIwYnR9neC/EEePP+jEheHYaDGuijc/4HsoStlmVTEmtYf+e\nI/VdhmfU1QKBgQDB84UbrD25Lortk32spqQMQhHCXsIXUghZxhE1+BJC32H47yDf\nSQfuUvg/1D7pbywM0374xJIyaxRb1Gdeo1mzDefzAXpgHQIiNg3/qE1ylioV/2hX\nh3YwyPfu8xh9/8cWEqyxWYy/+ZUIE+Vg/mrzlM9g/HzC3T+R+HZkEbunAQKBgAhw\nv+5lW9OcVSPA6k9s7yMbY0Imc+eXy8EbDQa/hQsFEZ5XWjrYdij0p/kPcSabbykK\nazJruDXrhOujWBMfwoDH2e1HWrjdrS2lZqgV5CceNhFM45IKfvOn/euzDUq/Ai61\nMVuhFGL2WcJ5mpGusT2wvZVf3GMqLZWdMjW9S8WpAoGBAOMjWXqKCgxMTdwAHgvy\n7fQjyC4WgWyxoHEz3lQcp3ii98I1cLIO11XFvg4/4nzxZfDT2L4wSyRFrNytfLCU\nNwknxqrpxoqXELhzFLmoiHouwkPz2ofMWlgSNTpXT7CbYWGw+AYtWFcW8bkZutA6\nMXZ8dgmrnxf48Uien1gzahDt\n-----END PRIVATE KEY-----\n";

#[tokio::test]
async fn github_installation_token_request_uses_app_jwt() {
    let recorded: Recorded = Arc::new(Mutex::new(None));
    let app = Router::new()
        .route(
            "/app/installations/:id/access_tokens",
            post(github_handler).delete(github_revoke_handler),
        )
        .with_state(recorded.clone());
    let base = spawn(app).await;

    let issuer = GithubIssuer::new(GithubConfig {
        app_id: 123456,
        private_key_pem: TEST_RSA_KEY.to_string(),
        api_base: base,
    });

    let credential = issuer
        .issue(&request(
            "github:pulls.create",
            json!({"installation_id": 42}),
        ))
        .await
        .unwrap();

    match credential.material {
        CredentialMaterial::Bearer { token, expiration } => {
            assert_eq!(token, "ghs_test");
            assert_eq!(expiration.as_deref(), Some("2026-09-15T13:00:00Z"));
        }
        other => panic!("expected bearer material, got {other:?}"),
    }

    let (headers, _) = recorded.lock().unwrap().clone().unwrap();
    let auth = headers.get("authorization").unwrap().to_str().unwrap();
    let jwt = auth.strip_prefix("Bearer ").expect("expected Bearer JWT");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have three segments");

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .unwrap();
    let header: Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
}

#[tokio::test]
async fn github_revokes_issued_credential() {
    let recorded: Recorded = Arc::new(Mutex::new(None));
    let app = Router::new()
        .route(
            "/app/installations/:id/access_tokens",
            post(github_handler).delete(github_revoke_handler),
        )
        .with_state(recorded.clone());
    let base = spawn(app).await;

    let issuer = GithubIssuer::new(GithubConfig {
        app_id: 123456,
        private_key_pem: TEST_RSA_KEY.to_string(),
        api_base: base,
    });

    let credential = issuer
        .issue(&request(
            "github:pulls.create",
            json!({"installation_id": 42}),
        ))
        .await
        .unwrap();
    let reference = credential.reference.clone().expect("credential reference");
    assert!(reference.starts_with("cred_github_"));

    assert_eq!(
        issuer.revoke_credential("t", &reference).await.unwrap(),
        RevokeEffect::Revoked
    );
    // second attempt: already revoked
    assert_eq!(
        issuer.revoke_credential("t", &reference).await.unwrap(),
        RevokeEffect::NotFound
    );
    // unknown reference for another provider is not this issuer's concern
    assert_eq!(
        issuer.revoke_credential("t", "cred_aws_xyz").await.unwrap(),
        RevokeEffect::NotFound
    );
}

async fn iam_handler(State(recorded): State<Recorded>, body: Bytes) -> (StatusCode, &'static str) {
    *recorded.lock().unwrap() =
        Some((HeaderMap::new(), String::from_utf8_lossy(&body).to_string()));
    (
        StatusCode::OK,
        r#"<PutRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"/>"#,
    )
}

#[tokio::test]
async fn aws_sts_revocation_attaches_deny_policy() {
    // STS mock issues credentials.
    let sts_recorded: Recorded = Arc::new(Mutex::new(None));
    let sts_app = Router::new()
        .route("/", post(sts_handler))
        .with_state(sts_recorded);
    let sts_base = spawn(sts_app).await;

    // IAM mock records the PutRolePolicy request.
    let iam_recorded: Recorded = Arc::new(Mutex::new(None));
    let iam_app = Router::new()
        .route("/", post(iam_handler))
        .with_state(iam_recorded.clone());
    let iam_base = spawn(iam_app).await;

    let issuer = AwsStsIssuer::new(AwsConfig {
        region: "us-east-1".into(),
        role_arn: "arn:aws:iam::123456789012:role/tessera-agent".into(),
        session_name: "tessera-agent".into(),
        access_key_id: "AKIDEXAMPLE".into(),
        secret_access_key: "secret".into(),
        session_token: None,
        endpoint_override: Some(sts_base),
        iam_endpoint_override: Some(iam_base),
    });

    let credential = issuer
        .issue(&request(
            "aws:s3:GetObject",
            json!({"resource_arn": "arn:aws:s3:::reports/x"}),
        ))
        .await
        .unwrap();
    let reference = credential.reference.clone().expect("credential reference");
    assert!(reference.starts_with("cred_aws_"));

    assert_eq!(
        issuer.revoke_credential("t", &reference).await.unwrap(),
        RevokeEffect::Revoked
    );

    let (_, body) = iam_recorded.lock().unwrap().clone().unwrap();
    assert!(body.contains("Action=PutRolePolicy"));
    assert!(body.contains("PolicyName=tessera-revoke-tessera-agent-agent-1"));
    assert!(body.contains("sts%3ARoleSessionName"));
    assert!(body.contains("RoleName=tessera-agent"));

    // second attempt: already revoked
    assert_eq!(
        issuer.revoke_credential("t", &reference).await.unwrap(),
        RevokeEffect::NotFound
    );
    // another tenant cannot revoke
    assert_eq!(
        issuer.revoke_credential("other", &reference).await.unwrap(),
        RevokeEffect::NotFound
    );
}

#[tokio::test]
async fn github_ttl_is_capped_at_one_hour() {
    let recorded: Recorded = Arc::new(Mutex::new(None));
    let app = Router::new()
        .route(
            "/app/installations/:id/access_tokens",
            post(github_handler).delete(github_revoke_handler),
        )
        .with_state(recorded.clone());
    let base = spawn(app).await;

    let issuer = GithubIssuer::new(GithubConfig {
        app_id: 123456,
        private_key_pem: TEST_RSA_KEY.to_string(),
        api_base: base,
    });

    let mut req = request("github:pulls.create", json!({"installation_id": 42}));
    req.ttl_seconds = 7200;
    let credential = issuer.issue(&req).await.unwrap();
    assert_eq!(
        credential.ttl_seconds,
        tessera_broker::issuers::github::GITHUB_MAX_TTL_SECONDS,
        "the broker must never claim a TTL longer than GitHub enforces"
    );
}
