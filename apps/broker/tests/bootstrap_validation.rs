//! Startup validation: operator-configured endpoints are checked (fail closed).

use tessera_broker::bootstrap;
use tessera_broker::config::{AwsConfig, BrokerConfig, GithubConfig, StripeConfig};

const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

fn cfg() -> BrokerConfig {
    BrokerConfig {
        signing_key_hex: Some(TEST_KEY.into()),
        verifying_contract: "0x0000000000000000000000000000000000000000".into(),
        chain_id: 84532,
        demo_allow: true,
        ..Default::default()
    }
}

fn aws(endpoint: Option<String>) -> AwsConfig {
    AwsConfig {
        region: "us-east-1".into(),
        role_arn: "arn:aws:iam::123456789012:role/tessera".into(),
        session_name: "tessera".into(),
        access_key_id: "AKIA".into(),
        secret_access_key: "secret".into(),
        session_token: None,
        endpoint_override: endpoint,
        iam_endpoint_override: None,
    }
}

#[tokio::test]
async fn valid_endpoints_build() {
    let mut config = cfg();
    config.github = Some(GithubConfig {
        app_id: 1,
        private_key_pem: "not-a-pem".into(),
        api_base: "https://api.github.com".into(),
    });
    config.stripe = Some(StripeConfig {
        restricted_keys: Default::default(),
        api_base: "https://api.stripe.com".into(),
    });
    config.aws = Some(aws(Some("https://sts.us-east-1.amazonaws.com".into())));
    if let Err(e) = bootstrap::build_service(&config).await {
        panic!("valid config rejected: {e}");
    }
}

#[tokio::test]
async fn malformed_github_endpoint_is_rejected() {
    let mut config = cfg();
    config.github = Some(GithubConfig {
        app_id: 1,
        private_key_pem: "not-a-pem".into(),
        api_base: "file:///etc/passwd".into(),
    });
    let err = bootstrap::build_service(&config)
        .await
        .err()
        .expect("expected a startup error");
    assert!(
        err.to_string().contains("GITHUB_API_BASE"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn credential_bearing_aws_endpoint_is_rejected() {
    let mut config = cfg();
    config.aws = Some(aws(Some("http://user:pass@sts.example".into())));
    let err = bootstrap::build_service(&config)
        .await
        .err()
        .expect("expected a startup error");
    assert!(
        err.to_string().contains("AWS_STS_ENDPOINT"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn operator_anchor_rpc_may_be_private_but_must_be_http() {
    use tessera_broker::config::AnchorConfig;

    let mut local = cfg();
    local.anchor = Some(AnchorConfig {
        rpc_url: "http://127.0.0.1:8545".into(),
        private_key: Some(TEST_KEY.into()),
        contract: "0x0000000000000000000000000000000000000001".into(),
    });
    assert!(bootstrap::build_service(&local).await.is_ok());

    let mut bad = cfg();
    bad.anchor = Some(AnchorConfig {
        rpc_url: "file:///etc/passwd".into(),
        private_key: Some(TEST_KEY.into()),
        contract: "0x0000000000000000000000000000000000000001".into(),
    });
    let err = bootstrap::build_service(&bad)
        .await
        .err()
        .expect("expected a startup error");
    assert!(err.to_string().contains("ANCHOR rpc_url"));
}
