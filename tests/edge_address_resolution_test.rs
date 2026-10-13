use ifoxy_windows::vpn::edge_resolver::{DnsResolver, EdgeResolutionError, EdgeResolver};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct MockResolver {
    call_count: Arc<AtomicUsize>,
    results: Vec<SocketAddr>,
}

impl DnsResolver for MockResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, EdgeResolutionError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(self.results.clone())
    }
}

struct FailingResolver;

impl DnsResolver for FailingResolver {
    fn resolve(&self, host: &str, _port: u16) -> Result<Vec<SocketAddr>, EdgeResolutionError> {
        Err(EdgeResolutionError::DnsLookupFailed(host.to_string()))
    }
}

#[test]
fn test_edge_address_pins_to_single_resolution() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mock = MockResolver {
        call_count: call_count.clone(),
        results: vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(151, 101, 1, 140)), 443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(151, 101, 65, 140)), 443),
        ],
    };

    let resolver = EdgeResolver::with_resolver(Box::new(mock));

    // First call: resolves from DNS
    let addr1 = resolver
        .resolve_and_pin("fra-edge.fastly.net", 443)
        .expect("First resolution should succeed");
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        addr1,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(151, 101, 1, 140)), 443)
    );

    // Second call: must return cached pinned address without touching DNS again (C4)
    let addr2 = resolver
        .resolve_and_pin("fra-edge.fastly.net", 443)
        .expect("Second resolution should succeed from cache");
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "DNS resolver must NOT be called twice"
    );
    assert_eq!(addr1, addr2, "Pinned address must be identical");

    // Extract IPv4
    let ipv4 = EdgeResolver::extract_ipv4(&addr1);
    assert_eq!(ipv4, Ipv4Addr::new(151, 101, 1, 140));

    // Clear cache, next call must re-resolve
    resolver.clear_cache();
    let addr3 = resolver
        .resolve_and_pin("fra-edge.fastly.net", 443)
        .expect("Third resolution after cache clear");
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "Resolver should be called once after clear"
    );
    assert_eq!(addr3, addr1);
}

#[test]
fn test_edge_address_filters_ipv6_and_selects_first_ipv4() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mock = MockResolver {
        call_count: call_count.clone(),
        results: vec![
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443), // IPv6 first
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443), // IPv4 second
        ],
    };

    let resolver = EdgeResolver::with_resolver(Box::new(mock));
    let addr = resolver
        .resolve_and_pin("edge.example.com", 443)
        .expect("Should pick IPv4");
    assert_eq!(
        addr,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443)
    );
}

#[test]
fn test_edge_address_rejects_ipv6_only() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mock = MockResolver {
        call_count: call_count.clone(),
        results: vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443)],
    };

    let resolver = EdgeResolver::with_resolver(Box::new(mock));
    let err = resolver
        .resolve_and_pin("ipv6-only.example.com", 443)
        .expect_err("IPv6-only must be rejected");
    assert_eq!(
        err,
        EdgeResolutionError::NoIpv4Address("ipv6-only.example.com".to_string())
    );
}

#[test]
fn test_edge_address_failing_dns() {
    let resolver = EdgeResolver::with_resolver(Box::new(FailingResolver));
    let err = resolver
        .resolve_and_pin("nonexistent.invalid", 443)
        .expect_err("DNS failure must be propagated");
    assert_eq!(
        err,
        EdgeResolutionError::DnsLookupFailed("nonexistent.invalid".to_string())
    );
}

#[test]
fn test_edge_address_real_system_resolution() {
    let resolver = EdgeResolver::new();
    let addr = resolver
        .resolve_and_pin("127.0.0.1", 8080)
        .expect("Localhost resolution");
    assert_eq!(
        addr,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    );
}
