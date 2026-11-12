//! Tessera Agent Action Broker (library).
//!
//! Authorizes an agent tool call and issues a single-use, short-lived credential scoped
//! to the declared intent. Every decision produces a signed receipt.

pub mod alert_acks;
pub mod alert_acks_pg;
pub mod alerts;
pub mod alerts_pg;
pub mod anchoring;
pub mod anchoring_pg;
pub mod auth;
pub mod auth_pg;
pub mod authority;
pub mod authorize;
pub mod bootstrap;
pub mod cache;
pub mod canonical;
pub mod chain;
pub mod chain_checkpoints;
pub mod chain_checkpoints_pg;
pub mod chain_pg;
pub mod clientip;
pub mod config;
pub mod db;
pub mod error;
pub mod eth;
pub mod export;
pub mod http;
pub mod issuers;
pub mod key_events;
pub mod key_events_pg;
pub mod merkle;
pub mod metrics;
pub mod netguard;
pub mod policy;
pub mod policy_pg;
pub mod proxy;
pub mod quota;
pub mod ratelimit;
pub mod receipt;
pub mod remediation;
pub mod remediation_pg;
pub mod revocation;
pub mod revocation_pg;
pub mod scheduler;
pub mod secrets;
pub mod signer;
pub mod telemetry;
pub mod telemetry_pg;
pub mod tool_pins;
pub mod tool_pins_pg;
pub mod verify;

pub use auth::{ApiKeyRecord, ApiKeyStore, MemoryApiKeyStore, Tenant};
pub use authorize::{AuthorizeRequest, AuthorizeResponse, Decision, RecordRequest, RecordResponse};
pub use chain::{ChainEntry, ChainStore, MemoryChainStore};
pub use error::BrokerError;
pub use http::AppState;
pub use receipt::GrantReceipt;
