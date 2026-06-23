//! Shared HTTP-fetch SSRF hardening for attacker-influenced URLs.
//!
//! Certificate-validation material — CRL distribution points (RFC 5280
//! §4.2.1.13) and AIA `caIssuers`/OCSP URLs (RFC 5280 §4.2.2.1) — is carried
//! *inside the certificate under validation*, so the fetch target is
//! attacker-controlled. Without a guard, presenting a crafted certificate turns
//! the validator into a Server-Side Request Forgery gadget: `http://127.0.0.1/`,
//! `http://169.254.169.254/` (cloud metadata), or any RFC 1918 host. A scheme
//! allowlist alone does not close this — `http://169.254.169.254/` passes a
//! scheme check yet still reaches an internal endpoint — so the guard also
//! filters the *resolved destination address*.
//!
//! This module is the single source of truth for those controls, originally
//! introduced for the CRL fetch path (ADR-0010) and shared with the AIA
//! chain-builder so both paths apply identical filtering rather than duplicating
//! the logic.
//!
//! Controls provided:
//! - [`validate_fetch_url`] — `http`/`https` scheme allowlist **and**
//!   resolved-IP filtering (loopback, private, link-local/metadata, unique-local,
//!   multicast, CGNAT, ...), run before any network egress.
//! - [`hardened_http_client`] — a `reqwest::Client` whose redirect policy is
//!   bounded ([`MAX_REDIRECTS`]) and refuses to follow redirects to literal
//!   non-public addresses.
//! - [`is_disallowed_ip`] — the address classifier shared by both.
//!
//! **Residual limitation (documented, not silently ignored).** Resolution here
//! and `reqwest`'s connect-time resolution are two separate lookups, so a
//! DNS-rebinding attacker who flips the record between them is not fully
//! prevented, and a redirect to a *hostname* that resolves internally is only
//! caught for literal-IP targets. Fully closing these would require pinning the
//! validated IP into the connection (custom resolver / per-request client).

use std::net::{IpAddr, Ipv4Addr};

use reqwest::Client;

/// Maximum HTTP redirects followed by a [`hardened_http_client`].
pub const MAX_REDIRECTS: usize = 5;

/// Classify an IPv4 address as non-public (loopback, private, link-local,
/// unspecified, broadcast, documentation, multicast, or RFC 6598 CGNAT shared
/// space).
fn is_disallowed_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_multicast()
        // CGNAT shared address space 100.64.0.0/10 (RFC 6598)
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
}

/// Classify an IP address as non-public, so an SSRF guard can refuse fetches
/// whose host resolves to an internal or metadata address. IPv4-mapped IPv6
/// addresses are unwrapped and re-checked.
pub fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_disallowed_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_disallowed_ipv4(v4);
            }
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique local fc00::/7
                || (first & 0xfe00) == 0xfc00
                // link-local unicast fe80::/10
                || (first & 0xffc0) == 0xfe80
        }
    }
}

/// Strip the brackets `reqwest`/`url` place around IPv6 literal hosts
/// (`[::1]`) so the inner address can be parsed.
fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Build an HTTP client with a bounded redirect policy that refuses to follow
/// redirects to literal non-public addresses — complementing the resolve-time
/// check in [`validate_fetch_url`].
///
/// Fails closed: a build failure (system/TLS fault, on which
/// `reqwest::Client::new()` would itself panic) panics rather than silently
/// degrading to `reqwest`'s default (unhardened) redirect behaviour.
pub fn hardened_http_client() -> Client {
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        if let Some(host) = attempt.url().host_str() {
            if let Ok(ip) = unbracket(host).parse::<IpAddr>() {
                if is_disallowed_ip(ip) {
                    // Stop following; the caller sees the 3xx and rejects it.
                    return attempt.stop();
                }
            }
        }
        attempt.follow()
    });
    Client::builder()
        .redirect(policy)
        .build()
        .expect("failed to build hardened HTTP client")
}

/// An error from [`validate_fetch_url`], with a category so callers can wrap it
/// in their own domain error type with an appropriate message prefix.
#[derive(Debug)]
pub enum UrlGuardError {
    /// The URL did not parse.
    Parse(String),
    /// The scheme was not `http`/`https`.
    Scheme(String),
    /// The URL had no host component.
    NoHost,
    /// DNS resolution failed (task error or lookup error).
    Resolution(String),
    /// The host resolved to no addresses.
    NoAddresses(String),
    /// The host is (or resolves to) a non-public address — SSRF guard.
    NonPublic(String),
}

impl std::fmt::Display for UrlGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlGuardError::Parse(m) => write!(f, "invalid URL: {m}"),
            UrlGuardError::Scheme(s) => {
                write!(
                    f,
                    "URL scheme not allowed: {s} (only http/https are supported)"
                )
            }
            UrlGuardError::NoHost => write!(f, "URL has no host"),
            UrlGuardError::Resolution(m) => write!(f, "failed to resolve host: {m}"),
            UrlGuardError::NoAddresses(h) => write!(f, "host {h} resolved to no addresses"),
            UrlGuardError::NonPublic(m) => {
                write!(f, "host {m} is a non-public address (SSRF guard)")
            }
        }
    }
}

/// Validate that a URL is safe to fetch before any network egress.
///
/// Enforces an `http`/`https` scheme allowlist **and** resolves the host,
/// rejecting the fetch when any resolved address is loopback, private,
/// link-local, unique-local, multicast, or otherwise non-public. Scheme
/// filtering alone does not stop SSRF (see the module docs); the destination
/// address is the thing that matters.
///
/// A literal-IP host is checked directly (no DNS). A hostname is resolved off
/// the async executor (via `spawn_blocking`) and **every** resolved address is
/// checked.
pub async fn validate_fetch_url(url: &str) -> Result<(), UrlGuardError> {
    let parsed =
        reqwest::Url::parse(url).map_err(|e| UrlGuardError::Parse(format!("{url}: {e}")))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(UrlGuardError::Scheme(other.to_string())),
    }
    let host = parsed.host_str().ok_or(UrlGuardError::NoHost)?;
    let host_bare = unbracket(host);

    // A literal IP needs no DNS — check it directly.
    if let Ok(ip) = host_bare.parse::<IpAddr>() {
        if is_disallowed_ip(ip) {
            return Err(UrlGuardError::NonPublic(host_bare.to_string()));
        }
        return Ok(());
    }

    // Hostname: resolve off the async executor and reject any non-public
    // destination among the resolved addresses.
    let port = parsed.port_or_known_default().unwrap_or(0);
    let host_owned = host_bare.to_string();
    let host_for_lookup = host_owned.clone();
    let addrs: Vec<std::net::SocketAddr> = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        (host_for_lookup.as_str(), port)
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<_>>())
    })
    .await
    .map_err(|e| UrlGuardError::Resolution(format!("DNS resolution task failed: {e}")))?
    .map_err(|e| UrlGuardError::Resolution(format!("{host_owned}: {e}")))?;

    if addrs.is_empty() {
        return Err(UrlGuardError::NoAddresses(host_owned));
    }
    for addr in &addrs {
        if is_disallowed_ip(addr.ip()) {
            return Err(UrlGuardError::NonPublic(format!(
                "{host_owned} resolves to non-public address {}",
                addr.ip()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_metadata_are_disallowed() {
        assert!(is_disallowed_ip("127.0.0.1".parse().unwrap()));
        assert!(is_disallowed_ip("169.254.169.254".parse().unwrap()));
        assert!(is_disallowed_ip("10.0.0.1".parse().unwrap()));
        assert!(is_disallowed_ip("192.168.1.1".parse().unwrap()));
        assert!(is_disallowed_ip("172.16.0.1".parse().unwrap()));
        assert!(is_disallowed_ip("100.64.0.1".parse().unwrap())); // CGNAT
        assert!(is_disallowed_ip("::1".parse().unwrap()));
        assert!(is_disallowed_ip("fe80::1".parse().unwrap()));
        assert!(is_disallowed_ip("fc00::1".parse().unwrap()));
        // IPv4-mapped loopback
        assert!(is_disallowed_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn public_addresses_are_allowed() {
        assert!(!is_disallowed_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_disallowed_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_disallowed_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn rejects_non_http_scheme() {
        let err = validate_fetch_url("file:///etc/passwd").await.unwrap_err();
        assert!(matches!(err, UrlGuardError::Scheme(_)));
    }

    #[tokio::test]
    async fn rejects_literal_loopback() {
        let err = validate_fetch_url("http://127.0.0.1/x").await.unwrap_err();
        assert!(matches!(err, UrlGuardError::NonPublic(_)));
    }

    #[tokio::test]
    async fn rejects_literal_metadata() {
        let err = validate_fetch_url("http://169.254.169.254/latest/meta-data/")
            .await
            .unwrap_err();
        assert!(matches!(err, UrlGuardError::NonPublic(_)));
    }
}
