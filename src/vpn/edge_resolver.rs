use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum EdgeResolutionError {
    #[error("DNS resolution failed for host: {0}")]
    DnsLookupFailed(String),
    #[error("No IPv4 address found for edge server: {0}")]
    NoIpv4Address(String),
}

pub trait DnsResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EdgeResolutionError>;
}

pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EdgeResolutionError> {
        let addr_str = format!("{}:{}", host, port);
        match addr_str.to_socket_addrs() {
            Ok(addrs) => Ok(addrs.collect()),
            Err(_) => Err(EdgeResolutionError::DnsLookupFailed(host.to_string())),
        }
    }
}

/// Thread-safe edge address resolver and pin cache (C4).
///
/// Ensures an upstream edge host is resolved once, selecting an IPv4 address,
/// and pinning it for the duration of the session so host route installation
/// and TLS transport connect to the identical IPv4 address.
pub struct EdgeResolver {
    resolver: Box<dyn DnsResolver>,
    cache: Arc<Mutex<HashMap<String, SocketAddr>>>,
}

impl EdgeResolver {
    pub fn new() -> Self {
        Self {
            resolver: Box::new(SystemDnsResolver),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_resolver(resolver: Box<dyn DnsResolver>) -> Self {
        Self {
            resolver,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Resolve edge server host and port to a pinned IPv4 SocketAddr.
    /// If already resolved, returns the cached address without re-resolving.
    pub fn resolve_and_pin(
        &self,
        host: &str,
        port: u16,
    ) -> Result<SocketAddr, EdgeResolutionError> {
        let key = format!("{}:{}", host.to_lowercase(), port);

        let mut cache = self.cache.lock().unwrap();
        if let Some(cached) = cache.get(&key) {
            return Ok(*cached);
        }

        let addrs = self.resolver.resolve(host, port)?;
        let ipv4_addr = addrs
            .into_iter()
            .find(|sa| sa.is_ipv4())
            .ok_or_else(|| EdgeResolutionError::NoIpv4Address(host.to_string()))?;

        cache.insert(key, ipv4_addr);
        Ok(ipv4_addr)
    }

    /// Extract IPv4 address from the resolved socket address.
    pub fn extract_ipv4(addr: &SocketAddr) -> Ipv4Addr {
        match addr.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => unreachable!("EdgeResolver guarantees IPv4 addresses"),
        }
    }

    /// Invalidate cache for a specific host and port or all hosts.
    pub fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
    }
}

impl Default for EdgeResolver {
    fn default() -> Self {
        Self::new()
    }
}
