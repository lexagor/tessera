//! Broker error type.

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("policy denied: {0}")]
    Denied(String),
    #[error("issuer error: {0}")]
    Issuer(String),
    #[error("receipt error: {0}")]
    Receipt(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("throttled: {0}")]
    Throttled(String),
    #[error("not configured: {0}")]
    NotConfigured(String),
    #[error("internal error: {0}")]
    Internal(String),
}
