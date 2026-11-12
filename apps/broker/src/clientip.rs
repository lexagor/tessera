//! Client IP resolution behind a reverse proxy.
//!
//! `ConnectInfo` gives the TCP peer, which is the proxy when the broker runs behind one
//! (Caddy/Docker). Trusting `X-Forwarded-For` unconditionally would let any direct client
//! spoof its address and dodge per-IP limits, so forwarded headers are honored **only**
//! when the peer is a configured trusted proxy, and the rightmost untrusted hop wins.

use std::net::IpAddr;

use crate::error::BrokerError;

/// Parsed `TRUSTED_PROXIES` allowlist (CIDRs, bare IPs, or `any`).
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    any: bool,
    cidrs: Vec<(IpAddr, u8)>,
}

impl TrustedProxies {
    pub fn new(entries: &[String]) -> Self {
        let mut any = false;
        let mut cidrs = Vec::new();
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if entry.eq_ignore_ascii_case("any") {
                any = true;
                continue;
            }
            if let Ok((addr, bits)) = parse_cidr(entry) {
                cidrs.push((addr, bits));
            }
        }
        Self { any, cidrs }
    }

    pub fn from_env() -> Self {
        let entries = std::env::var("TRUSTED_PROXIES")
            .ok()
            .map(|raw| raw.split(',').map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_default();
        Self::new(&entries)
    }

    pub fn is_enabled(&self) -> bool {
        self.any || !self.cidrs.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        if self.any {
            return true;
        }
        self.cidrs
            .iter()
            .any(|(net, bits)| in_network(ip, *net, *bits))
    }

    /// Resolve the client address: the peer unless the peer is a trusted proxy, in which
    /// case the rightmost untrusted `X-Forwarded-For` hop (falling back to the peer).
    pub fn client_ip(&self, peer: IpAddr, forwarded_for: Option<&str>) -> IpAddr {
        if !self.contains(peer) {
            return peer;
        }
        let Some(header) = forwarded_for else {
            return peer;
        };
        let mut hops: Vec<IpAddr> = header
            .split(',')
            .filter_map(|hop| hop.trim().parse::<IpAddr>().ok())
            .collect();
        if hops.is_empty() {
            return peer;
        }
        // Walk right-to-left past trusted proxies; the first untrusted hop is the client.
        while let Some(hop) = hops.pop() {
            if !self.contains(hop) {
                return hop;
            }
        }
        // Every hop is a trusted proxy: use the leftmost value as a best effort.
        header
            .split(',')
            .find_map(|hop| hop.trim().parse::<IpAddr>().ok())
            .unwrap_or(peer)
    }
}

fn parse_cidr(entry: &str) -> Result<(IpAddr, u8), BrokerError> {
    match entry.split_once('/') {
        Some((addr, bits)) => {
            let addr: IpAddr = addr
                .parse()
                .map_err(|_| BrokerError::Invalid(format!("bad trusted proxy '{entry}'")))?;
            let bits: u8 = bits
                .parse()
                .map_err(|_| BrokerError::Invalid(format!("bad trusted proxy '{entry}'")))?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if bits > max {
                return Err(BrokerError::Invalid(format!("bad prefix in '{entry}'")));
            }
            Ok((addr, bits))
        }
        None => {
            let addr: IpAddr = entry
                .parse()
                .map_err(|_| BrokerError::Invalid(format!("bad trusted proxy '{entry}'")))?;
            let bits = if addr.is_ipv4() { 32 } else { 128 };
            Ok((addr, bits))
        }
    }
}

fn in_network(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits as u32)
            };
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = if bits == 0 {
                0u128
            } else {
                u128::MAX << (128 - bits as u32)
            };
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_header() {
        let trusted = TrustedProxies::new(&["10.0.0.0/8".into()]);
        let peer = ip("203.0.113.9");
        assert_eq!(
            trusted.client_ip(peer, Some("1.2.3.4")),
            peer,
            "direct clients must not be able to spoof XFF"
        );
        assert_eq!(trusted.client_ip(peer, None), peer);
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted_hop() {
        let trusted = TrustedProxies::new(&["10.0.0.0/8".into(), "172.16.0.0/12".into()]);
        let peer = ip("172.18.0.5"); // the proxy
        assert_eq!(
            trusted.client_ip(peer, Some("198.51.100.7")),
            ip("198.51.100.7")
        );
        // client -> proxy1 -> proxy2(peer): skip trusted hops to find the client
        assert_eq!(
            trusted.client_ip(peer, Some("198.51.100.7, 10.1.2.3")),
            ip("198.51.100.7")
        );
        // all hops trusted -> leftmost fallback
        assert_eq!(
            trusted.client_ip(peer, Some("10.1.2.3, 10.4.5.6")),
            ip("10.1.2.3")
        );
    }

    #[test]
    fn garbage_and_any_mode() {
        let any = TrustedProxies::new(&["any".into()]);
        assert!(any.is_enabled());
        assert_eq!(
            any.client_ip(ip("9.9.9.9"), Some("not-an-ip, 8.8.8.8")),
            ip("8.8.8.8")
        );
        assert_eq!(any.client_ip(ip("9.9.9.9"), Some("garbage")), ip("9.9.9.9"));

        let disabled = TrustedProxies::default();
        assert!(!disabled.is_enabled());
        assert_eq!(
            disabled.client_ip(ip("9.9.9.9"), Some("8.8.8.8")),
            ip("9.9.9.9")
        );
    }

    #[test]
    fn cidr_matching_is_bounded() {
        let trusted = TrustedProxies::new(&["192.168.1.0/24".into(), "::1".into()]);
        assert!(trusted.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))));
        assert!(!trusted.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
        assert!(trusted.contains(ip("::1")));
    }
}
