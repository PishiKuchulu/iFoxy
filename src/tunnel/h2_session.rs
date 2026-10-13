use super::stream::TunneledStream;
use bytes::Bytes;
use h2::client::{self, SendRequest};
use h2::PingPong;
use http::{Method, Request, StatusCode, Uri};
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tokio::sync::Mutex as TokioMutex;
use tokio_rustls::TlsConnector;

pub const MOZILLA_VPN_USER_AGENT: &str = "MozillaVPN/2.35.0 (sys:linux; iap:true)";

#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("HTTP/2 protocol error: {0}")]
    H2(#[from] h2::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),
    #[error("Server rejected CONNECT tunnel with status: {0}")]
    ConnectRejected(StatusCode),
    #[error("Invalid server authority: {0}")]
    InvalidAuthority(String),
    #[error("Tunnel session not connected")]
    NotConnected,
    #[error("DNS resolution error: {0}")]
    DnsResolution(String),
}

pub fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

pub fn build_connect_headers(
    authority: &str,
    bearer_token: &str,
) -> Result<Request<()>, TunnelError> {
    let uri: Uri = authority
        .parse()
        .map_err(|e: http::uri::InvalidUri| TunnelError::InvalidAuthority(e.to_string()))?;

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("proxy-authorization", format!("Bearer {}", bearer_token))
        .header("user-agent", MOZILLA_VPN_USER_AGENT)
        .body(())?;

    Ok(req)
}

#[derive(Default, Debug)]
pub struct TrafficMetrics {
    pub bytes_tx: std::sync::atomic::AtomicU64,
    pub bytes_rx: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
pub struct H2UpstreamSession {
    sender: Arc<TokioMutex<Option<SendRequest<Bytes>>>>,
    ping_pong: Arc<TokioMutex<Option<PingPong>>>,
    token: Arc<RwLock<String>>,
    connected_addr: Option<SocketAddr>,
    pub metrics: Arc<TrafficMetrics>,
    // Handle of the background task driving the h2 Connection to completion.
    // Aborting it forcibly closes the underlying TCP/TLS socket and stops any
    // further SupervisionEvent from being emitted by this (possibly stale)
    // session. Without this, disconnecting or reconnecting left the old
    // upstream connection physically open and able to emit events into a
    // forwarder that outlived the session (S-8 in the round-3 review).
    driver_handle: Arc<TokioMutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl H2UpstreamSession {
    #[cfg(any(test, feature = "test-doubles"))]
    pub fn new_dummy(token: &str) -> Self {
        Self {
            sender: Arc::new(TokioMutex::new(None)),
            ping_pong: Arc::new(TokioMutex::new(None)),
            token: Arc::new(RwLock::new(token.to_string())),
            connected_addr: None,
            metrics: Arc::new(TrafficMetrics::default()),
            driver_handle: Arc::new(TokioMutex::new(None)),
        }
    }

    pub fn from_send_request(send_request: SendRequest<Bytes>, bearer_token: &str) -> Self {
        Self {
            sender: Arc::new(TokioMutex::new(Some(send_request))),
            ping_pong: Arc::new(TokioMutex::new(None)),
            token: Arc::new(RwLock::new(bearer_token.to_string())),
            connected_addr: None,
            metrics: Arc::new(TrafficMetrics::default()),
            driver_handle: Arc::new(TokioMutex::new(None)),
        }
    }

    pub fn from_send_request_with_driver(
        send_request: SendRequest<Bytes>,
        bearer_token: &str,
        driver_handle: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            sender: Arc::new(TokioMutex::new(Some(send_request))),
            ping_pong: Arc::new(TokioMutex::new(None)),
            token: Arc::new(RwLock::new(bearer_token.to_string())),
            connected_addr: None,
            metrics: Arc::new(TrafficMetrics::default()),
            driver_handle: Arc::new(TokioMutex::new(Some(driver_handle))),
        }
    }

    /// Forcibly stops the background task driving this session's HTTP/2
    /// connection, closing the underlying socket. Must be called whenever a
    /// session is torn down (disconnect, or replaced during a reconnect) so
    /// that it cannot linger and emit stale SupervisionEvents, and so the
    /// TCP connection to the edge is not leaked open (S-8).
    pub async fn shutdown(&self) {
        let handle = self.driver_handle.lock().await.take();
        if let Some(h) = handle {
            h.abort();
            let _ = h.await;
        }
    }

    pub fn get_metrics(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.metrics.bytes_tx.load(Ordering::Relaxed),
            self.metrics.bytes_rx.load(Ordering::Relaxed),
        )
    }

    pub fn current_token(&self) -> String {
        self.token.read().unwrap().clone()
    }

    pub fn update_token(&self, new_token: &str) {
        if let Ok(mut lock) = self.token.write() {
            *lock = new_token.to_string();
        }
    }

    pub fn connected_addr(&self) -> Option<SocketAddr> {
        self.connected_addr
    }

    pub async fn connect_addr(
        edge_addr: SocketAddr,
        sni_hostname: &str,
        bearer_token: &str,
    ) -> Result<Self, TunnelError> {
        Self::connect_addr_with_supervision(edge_addr, sni_hostname, bearer_token, None, None).await
    }

    pub async fn connect_addr_with_supervision(
        edge_addr: SocketAddr,
        sni_hostname: &str,
        bearer_token: &str,
        supervision_tx: Option<
            tokio::sync::mpsc::Sender<crate::service::state_machine::SupervisionEvent>,
        >,
        bind_if_idx: Option<u32>,
    ) -> Result<Self, TunnelError> {
        Self::connect_addr_with_supervision_and_roots(
            edge_addr,
            sni_hostname,
            bearer_token,
            supervision_tx,
            bind_if_idx,
            None,
        )
        .await
    }

    pub async fn connect_addr_with_supervision_and_roots(
        edge_addr: SocketAddr,
        sni_hostname: &str,
        bearer_token: &str,
        supervision_tx: Option<
            tokio::sync::mpsc::Sender<crate::service::state_machine::SupervisionEvent>,
        >,
        bind_if_idx: Option<u32>,
        custom_roots: Option<RootCertStore>,
    ) -> Result<Self, TunnelError> {
        let root_store = match custom_roots {
            Some(roots) => roots,
            None => {
                let mut store = RootCertStore::empty();
                store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                store
            }
        };

        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec()];

        let connector = TlsConnector::from(Arc::new(client_config));

        let tcp = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let socket = if edge_addr.is_ipv4() {
                tokio::net::TcpSocket::new_v4()?
            } else {
                tokio::net::TcpSocket::new_v6()?
            };

            #[cfg(windows)]
            if let Some(if_idx) = bind_if_idx {
                if edge_addr.is_ipv4() {
                    use std::os::windows::io::AsRawSocket;
                    #[link(name = "ws2_32")]
                    extern "system" {
                        fn setsockopt(
                            s: usize,
                            level: i32,
                            optname: i32,
                            optval: *const u8,
                            optlen: i32,
                        ) -> i32;
                    }
                    let raw = socket.as_raw_socket() as usize;
                    let net_order = if_idx.to_be();
                    // SAFETY: setsockopt with IPPROTO_IP (0) and IP_UNICAST_IF (31) requires a 4-byte network-order interface index.
                    let res = unsafe {
                        setsockopt(
                            raw,
                            0,  // IPPROTO_IP
                            31, // IP_UNICAST_IF
                            &net_order as *const _ as *const u8,
                            std::mem::size_of_val(&net_order) as i32,
                        )
                    };
                    if res != 0 {
                        tracing::warn!(
                            "Failed to bind socket to physical interface {}: {}",
                            if_idx,
                            std::io::Error::last_os_error()
                        );
                    }
                }
            }

            socket.connect(edge_addr).await
        })
        .await
        .map_err(|_| {
            TunnelError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP connect timed out",
            ))
        })??;

        let server_name = ServerName::try_from(sni_hostname.to_string())
            .map_err(|e| TunnelError::Tls(e.to_string()))?;

        let tls_stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            connector.connect(server_name, tcp),
        )
        .await
        .map_err(|_| {
            TunnelError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TLS handshake timed out",
            ))
        })?
        .map_err(|e| TunnelError::Tls(e.to_string()))?;

        // HTTP/2 Window and Frame Tuning (H7)
        let mut builder = client::Builder::new();
        builder.initial_window_size(4 * 1024 * 1024); // 4 MiB per stream
        builder.initial_connection_window_size(8 * 1024 * 1024); // 8 MiB connection
        builder.max_frame_size(16384); // 16 KiB frame size

        let (send_request, mut connection) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            builder.handshake(tls_stream),
        )
        .await
        .map_err(|_| {
            TunnelError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "H2 handshake timed out",
            ))
        })??;
        let ping_pong = connection.ping_pong();

        // Drive the HTTP/2 connection in background, notifying supervision when dropped
        let driver_handle = tokio::spawn(async move {
            match connection.await {
                Ok(()) => {
                    tracing::info!("H2 upstream connection closed normally");
                    if let Some(tx) = supervision_tx {
                        let _ = tx
                            .send(
                                crate::service::state_machine::SupervisionEvent::ConnectionDropped,
                            )
                            .await;
                    }
                }
                Err(e) => {
                    tracing::warn!("H2 upstream connection terminated with error: {:?}", e);
                    if let Some(tx) = supervision_tx {
                        let event = if e.is_go_away() {
                            let code = e.reason().map(u32::from).unwrap_or(0);
                            crate::service::state_machine::SupervisionEvent::H2GoAway(code)
                        } else {
                            crate::service::state_machine::SupervisionEvent::ConnectionDropped
                        };
                        let _ = tx.send(event).await;
                    }
                }
            }
        });

        Ok(Self {
            sender: Arc::new(TokioMutex::new(Some(send_request))),
            ping_pong: Arc::new(TokioMutex::new(ping_pong)),
            token: Arc::new(RwLock::new(bearer_token.to_string())),
            connected_addr: Some(edge_addr),
            metrics: Arc::new(TrafficMetrics::default()),
            driver_handle: Arc::new(TokioMutex::new(Some(driver_handle))),
        })
    }

    pub async fn connect(
        edge_host: &str,
        edge_port: u16,
        bearer_token: &str,
    ) -> Result<Self, TunnelError> {
        let addr_str = format!("{}:{}", edge_host, edge_port);
        let socket_addr = addr_str
            .to_socket_addrs()
            .map_err(|e| TunnelError::DnsResolution(e.to_string()))?
            .next()
            .ok_or_else(|| {
                TunnelError::DnsResolution(format!("No address found for {}", edge_host))
            })?;

        Self::connect_addr(socket_addr, edge_host, bearer_token).await
    }

    pub async fn open_stream(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TunneledStream, TunnelError> {
        let authority = format_authority(target_host, target_port);
        let req = build_connect_headers(&authority, &self.current_token())?;

        // Clone sender under lock then DROP LOCK immediately before awaiting ready() (H7)
        let sender = {
            let sender_guard = self.sender.lock().await;
            sender_guard
                .as_ref()
                .ok_or(TunnelError::NotConnected)?
                .clone()
        };

        let mut ready_sender = sender.ready().await.map_err(TunnelError::H2)?;
        let (response_future, send_stream) = ready_sender.send_request(req, false)?;

        let response = response_future.await?;
        if response.status() != StatusCode::OK {
            return Err(TunnelError::ConnectRejected(response.status()));
        }

        let recv_stream = response.into_body();
        Ok(TunneledStream::new_with_metrics(
            recv_stream,
            send_stream,
            Some(self.metrics.clone()),
        ))
    }

    pub async fn ping(&self) -> Result<(), TunnelError> {
        self.ping_with_timeout(std::time::Duration::from_secs(5))
            .await
    }

    pub async fn ping_with_timeout(&self, timeout: std::time::Duration) -> Result<(), TunnelError> {
        let mut guard = self.ping_pong.lock().await;
        if let Some(pp) = guard.as_mut() {
            tokio::time::timeout(timeout, pp.ping(h2::Ping::opaque()))
                .await
                .map_err(|_| {
                    TunnelError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "PING deadline exceeded",
                    ))
                })?
                .map_err(TunnelError::H2)?;
            Ok(())
        } else {
            Err(TunnelError::NotConnected)
        }
    }
}
