//! Egress policy for tenant-supplied RPC URLs.
//!
//! A tenant may point their anchor target at any RPC endpoint, and the broker will then make
//! requests to it — an SSRF/port-scan primitive. This module validates the URL before it is
//! stored: scheme must be http(s), credentials are rejected, and private / loopback /
//! link-local / metadata addresses are refused unless the operator opts in or allowlists the
//! host.

use crate::error::BrokerError;

/// Shared outbound HTTP client with bounded connect/total timeouts.
pub fn outbound_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("outbound HTTP client configuration must be valid")
}

#[derive(Debug, Clone, Default)]
pub struct RpcPolicy {
    /// Allow loopback / RFC1918 / link-local targets (development only).
    allow_private: bool,
    /// Optional host[:port] allowlist; when non-empty, nothing else is accepted.
    allowlist: Vec<String>,
}

/// Extract `(host, port)` from an http(s) URL, rejecting non-http schemes, embedded
/// credentials, and whitespace/control characters.
pub fn host_of(url: &str) -> Result<(String, Option<String>), BrokerError> {
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(BrokerError::Invalid(
            "url contains whitespace/control characters".into(),
        ));
    }
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| BrokerError::Invalid("url must be http(s)".into()))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err(BrokerError::Invalid(
            "url must not contain credentials".into(),
        ));
    }
    let (host, port) = split_host_port(authority)?;
    if host.is_empty() {
        return Err(BrokerError::Invalid("url has no host".into()));
    }
    Ok((host, port))
}

/// Validate an operator-configured endpoint (shape only: scheme, credentials, host).
pub fn validate_endpoint(url: &str, label: &str) -> Result<(), BrokerError> {
    host_of(url).map(|_| ()).map_err(|e| match e {
        BrokerError::Invalid(msg) => BrokerError::Invalid(format!("{label}: {msg}")),
        other => other,
    })
}

/// Optional strict egress: when `EGRESS_ALLOWLIST` is set, outbound calls to any other host
/// are refused. Empty allowlist = permissive (operator-configured endpoints are trusted).
#[derive(Debug, Clone, Default)]
pub struct EgressGuard {
    allowlist: Vec<String>,
    allow_private: bool,
}

impl EgressGuard {
    pub fn new(allowlist: Vec<String>) -> Self {
        Self::new_with_private(allowlist, false)
    }

    pub fn new_with_private(allowlist: Vec<String>, allow_private: bool) -> Self {
        Self {
            allowlist: allowlist
                .into_iter()
                .map(|entry| entry.trim().to_ascii_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect(),
            allow_private,
        }
    }

    /// Permissive guard (tests/local).
    pub fn permissive() -> Self {
        Self::new_with_private(Vec::new(), true)
    }

    pub fn from_env() -> Self {
        let allowlist = std::env::var("EGRESS_ALLOWLIST")
            .ok()
            .map(|raw| raw.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        let allow_private = std::env::var("EGRESS_ALLOW_PRIVATE").as_deref() == Ok("1");
        Self::new_with_private(allowlist, allow_private)
    }

    pub fn is_enabled(&self) -> bool {
        !self.allowlist.is_empty()
    }

    /// Refuse a URL whose host is not on the allowlist (no-op when disabled).
    pub fn check(&self, url: &str) -> Result<(), BrokerError> {
        if self.allowlist.is_empty() {
            return Ok(());
        }
        let (host, port) = host_of(url)?;
        let host_port = match &port {
            Some(port) => format!("{host}:{port}"),
            None => host.clone(),
        };
        let ok = self
            .allowlist
            .iter()
            .any(|allowed| allowed == &host || allowed == &host_port);
        if ok {
            Ok(())
        } else {
            Err(BrokerError::Invalid(format!(
                "egress to '{host}' is not in EGRESS_ALLOWLIST"
            )))
        }
    }

    /// When strict egress is enabled, also reject DNS resolutions to private/reserved space.
    /// This closes the common "public allowlisted hostname resolves inside the network" case.
    pub async fn check_resolved(&self, url: &str) -> Result<(), BrokerError> {
        self.check(url)?;
        if !self.is_enabled() {
            return Ok(());
        }
        let (host, port) = host_of(url)?;
        if !self.allow_private && is_private_or_local(&host) {
            return Err(BrokerError::Invalid(format!(
                "egress to '{host}' resolves to private space"
            )));
        }
        let default_port = if url.starts_with("https://") { 443 } else { 80 };
        let port = port
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(default_port);
        let addresses = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| BrokerError::Invalid(format!("egress DNS lookup failed: {e}")))?;
        let mut found = false;
        for address in addresses {
            found = true;
            if !self.allow_private && is_private_or_local(&address.ip().to_string()) {
                return Err(BrokerError::Invalid(format!(
                    "egress to '{host}' resolves to private space"
                )));
            }
        }
        if !found {
            return Err(BrokerError::Invalid(format!(
                "egress host '{host}' did not resolve"
            )));
        }
        Ok(())
    }
}

impl RpcPolicy {
    pub fn new(allow_private: bool, allowlist: Vec<String>) -> Self {
        Self {
            allow_private,
            allowlist: allowlist
                .into_iter()
                .map(|entry| entry.trim().to_ascii_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect(),
        }
    }

    pub fn from_env() -> Self {
        let allow_private = std::env::var("ANCHOR_RPC_ALLOW_PRIVATE").as_deref() == Ok("1");
        let allowlist = std::env::var("ANCHOR_RPC_ALLOWLIST")
            .ok()
            .map(|raw| raw.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        Self::new(allow_private, allowlist)
    }

    /// Validate a tenant-supplied RPC URL.
    pub fn validate(&self, url: &str) -> Result<(), BrokerError> {
        if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(BrokerError::Invalid(
                "rpc url contains whitespace/control characters".into(),
            ));
        }
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .ok_or_else(|| BrokerError::Invalid("rpc url must be http(s)".into()))?;

        // Reject embedded credentials (user:pass@host) and fragments/queries in the authority.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.contains('@') {
            return Err(BrokerError::Invalid(
                "rpc url must not contain credentials".into(),
            ));
        }
        let (host, port) = split_host_port(authority)?;
        if host.is_empty() {
            return Err(BrokerError::Invalid("rpc url has no host".into()));
        }

        let host_port = match port {
            Some(port) => format!("{host}:{port}"),
            None => host.clone(),
        };
        if !self.allowlist.is_empty() {
            let ok = self
                .allowlist
                .iter()
                .any(|allowed| allowed == &host || allowed == &host_port);
            return if ok {
                Ok(())
            } else {
                Err(BrokerError::Invalid(
                    "rpc host is not in ANCHOR_RPC_ALLOWLIST".into(),
                ))
            };
        }

        if !self.allow_private && is_private_or_local(&host) {
            return Err(BrokerError::Invalid(
                "rpc host is private/loopback; set ANCHOR_RPC_ALLOW_PRIVATE=1 or allowlist it"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Split `host[:port]`, handling bracketed IPv6 literals.
fn split_host_port(authority: &str) -> Result<(String, Option<String>), BrokerError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| BrokerError::Invalid("malformed IPv6 rpc host".into()))?;
        let port = tail.strip_prefix(':').map(str::to_string);
        return Ok((host.to_ascii_lowercase(), port));
    }
    match authority.split_once(':') {
        Some((host, port)) => {
            let port = port.split(':').next().unwrap_or("").to_string(); // reject extra colons
            Ok((host.to_ascii_lowercase(), Some(port)))
        }
        None => Ok((authority.to_ascii_lowercase(), None)),
    }
}

fn private_ipv4(ip: [u8; 4]) -> bool {
    let [a, b, ..] = ip;
    a == 0
        || a == 10
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b))
}

fn is_private_or_local(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".internal") {
        return true;
    }
    if let Some(ip) = parse_ipv4(host) {
        return private_ipv4(ip);
    }
    // IPv6 literal (already de-bracketed), including IPv4-mapped forms.
    if host.contains(':') {
        let lower = host.to_ascii_lowercase();
        if let Some(mapped) = lower.strip_prefix("::ffff:") {
            if let Some(ip) = parse_ipv4(mapped) {
                return private_ipv4(ip);
            }
        }
        return lower == "::1"
            || lower.starts_with("fe80:")
            || lower.starts_with("fc")
            || lower.starts_with("fd")
            || lower == "::";
    }
    false
}

fn parse_ipv4(host: &str) -> Option<[u8; 4]> {
    let mut parts = [0u8; 4];
    let mut count = 0;
    for piece in host.split('.') {
        if count == 4 {
            return None;
        }
        parts[count] = piece.parse().ok()?;
        count += 1;
    }
    (count == 4).then_some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict() -> RpcPolicy {
        RpcPolicy::new(false, vec![])
    }

    #[test]
    fn accepts_public_https() {
        assert!(strict().validate("https://sepolia.base.org").is_ok());
        assert!(strict().validate("https://mainnet.base.org").is_ok());
    }

    #[test]
    fn rejects_non_http_schemes_and_junk() {
        for bad in [
            "file:///etc/passwd",
            "ftp://example.com",
            "sepolia.base.org",
            "http://user:pass@example.com",
            "https://example.com/\nHost: evil",
        ] {
            assert!(strict().validate(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn rejects_private_and_metadata_targets() {
        for bad in [
            "http://127.0.0.1:8545",
            "http://localhost:8545",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.5",
            "http://192.168.1.10",
            "http://172.16.5.5",
            "http://[::1]:8545",
            "http://metadata.google.internal",
        ] {
            assert!(strict().validate(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn allow_private_permits_local_dev() {
        let policy = RpcPolicy::new(true, vec![]);
        assert!(policy.validate("http://127.0.0.1:8545").is_ok());
        assert!(policy.validate("http://localhost:8545").is_ok());
        assert!(policy.validate("https://sepolia.base.org").is_ok());
    }

    #[test]
    fn endpoint_shape_validation() {
        assert!(validate_endpoint("https://sts.us-east-1.amazonaws.com", "aws").is_ok());
        assert!(validate_endpoint("http://127.0.0.1:8545", "rpc").is_ok()); // shape only
        let err = validate_endpoint("file:///etc/passwd", "aws").unwrap_err();
        assert!(err.to_string().contains("aws"));
        assert!(validate_endpoint("http://u:p@host", "gh").is_err());
    }

    #[test]
    fn egress_guard_blocks_unlisted_hosts_when_enabled() {
        let guard = EgressGuard::new(vec!["api.stripe.com".into(), "127.0.0.1:8545".into()]);
        assert!(guard.is_enabled());
        assert!(guard.check("https://api.stripe.com/v1/refunds").is_ok());
        assert!(guard.check("http://127.0.0.1:8545").is_ok());
        assert!(guard.check("https://evil.example/exfil").is_err());
        // host matches but port differs -> blocked
        assert!(guard.check("http://127.0.0.1:9999").is_err());

        // disabled guard is permissive
        let permissive = EgressGuard::permissive();
        assert!(!permissive.is_enabled());
        assert!(permissive.check("https://anything.example").is_ok());
    }

    #[tokio::test]
    async fn outbound_client_does_not_follow_redirects() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::Read;
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nConnection: close\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
        let response = outbound_client()
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 302);
    }

    #[tokio::test]
    async fn strict_egress_rejects_private_resolution() {
        let guard = EgressGuard::new(vec!["localhost".into()]);
        let error = guard
            .check_resolved("http://localhost:1234")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("private"));
        assert!(EgressGuard::permissive()
            .check_resolved("http://localhost:1234")
            .await
            .is_ok());
    }

    #[test]
    fn allowlist_restricts_to_named_hosts() {
        let policy = RpcPolicy::new(false, vec!["rpc.internal.example:8545".into()]);
        assert!(policy.validate("https://rpc.internal.example:8545").is_ok());
        assert!(policy.validate("https://rpc.internal.example").is_err()); // port must match
        assert!(policy.validate("https://sepolia.base.org").is_err());
    }
}
