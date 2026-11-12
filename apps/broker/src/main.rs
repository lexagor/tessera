//! Tessera Agent Action Broker — binary entrypoint.

use tessera_broker::bootstrap;
use tessera_broker::config::BrokerConfig;
use tessera_broker::http;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tessera_broker=debug,info".into()),
        )
        .init();

    let cfg = BrokerConfig::from_env();
    let state = bootstrap::build_state(&cfg).await?;

    state.service.migrate().await?;
    state.keys.migrate().await?;

    // The sweep also carries gap detection and scheduled archiving, so run it when any of
    // those is configured — not only when anchoring itself is enabled.
    if cfg.anchor_interval_secs.is_some() || cfg.archive_dir.is_some() {
        let secs = cfg.anchor_interval_secs.unwrap_or(60).max(1);
        tracing::info!(interval_secs = secs, "starting background scheduler");
        tessera_broker::scheduler::spawn(state.clone(), std::time::Duration::from_secs(secs));
    }

    if cfg.demo_allow {
        let (record, _) = state
            .keys
            .create(
                "default",
                "demo",
                Some(cfg.demo_key.clone()),
                Default::default(),
            )
            .await?;
        tracing::info!(prefix = %record.prefix, "seeded demo API key for tenant 'default'");
    }

    if let Some(tenant) = &cfg.bootstrap_tenant {
        let (record, key) = state
            .keys
            .create(tenant, "bootstrap", None, Default::default())
            .await?;
        println!("──────────────────────────────────────────────────────────────");
        println!(
            "TESSERA BOOTSTRAP API KEY  (tenant: {tenant}, id: {})",
            record.id
        );
        println!("  {key}");
        println!("Store it now; it will not be shown again.");
        println!("──────────────────────────────────────────────────────────────");
    }

    tracing::info!(
        signer = %state.service.signer.address_hex(),
        providers = ?state.service.issuers.providers(),
        demo = cfg.demo_allow,
        "tessera broker starting"
    );

    let addr = format!("{}:{}", cfg.host, cfg.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");
    axum::serve(
        listener,
        http::app(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
