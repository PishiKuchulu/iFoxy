use crate::tunnel::h2_session::H2UpstreamSession;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub const DEFAULT_LOCAL_PROXY_PORT: u16 = 10800;
pub const MAX_CONCURRENT_PROXY_CONNECTIONS: usize = 512;
pub const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const PROXY_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub async fn copy_bidirectional_with_idle<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout: Duration,
) -> Result<(), std::io::Error>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let (activity_tx, mut activity_rx) = tokio::sync::mpsc::channel::<()>(64);

    let tx_a = activity_tx.clone();
    let copy_a_to_b = async move {
        let mut buf = [0u8; 16384];
        loop {
            let n = a_read.read(&mut buf).await?;
            if n == 0 {
                let _ = b_write.shutdown().await;
                break;
            }
            let _ = tx_a.try_send(());
            b_write.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };

    let tx_b = activity_tx;
    let copy_b_to_a = async move {
        let mut buf = [0u8; 16384];
        loop {
            let n = b_read.read(&mut buf).await?;
            if n == 0 {
                let _ = a_write.shutdown().await;
                break;
            }
            let _ = tx_b.try_send(());
            a_write.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };

    let relay = async { tokio::try_join!(copy_a_to_b, copy_b_to_a) };
    tokio::pin!(relay);

    let idle_timer = async {
        loop {
            match tokio::time::timeout(idle_timeout, activity_rx.recv()).await {
                Ok(Some(())) => continue,
                Ok(None) => break,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Proxy relay idle timeout exceeded",
                    ));
                }
            }
        }
        Ok::<(), std::io::Error>(())
    };

    tokio::select! {
        res = &mut relay => res.map(|_| ()),
        idle_res = idle_timer => {
            match idle_res {
                Ok(()) => relay.await.map(|_| ()),
                Err(e) => Err(e),
            }
        }
    }
}

pub struct LocalProxyServer {
    running: Arc<AtomicBool>,
    active_connections: Arc<AtomicUsize>,
    cancel_token: CancellationToken,
    task_handles: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
}

impl LocalProxyServer {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            cancel_token: CancellationToken::new(),
            task_handles: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

impl Default for LocalProxyServer {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalProxyServer {
    pub fn start(&self, port: u16, upstream: Arc<H2UpstreamSession>) -> JoinHandle<()> {
        let running = self.running.clone();
        let active_conns = self.active_connections.clone();
        let cancel_token = self.cancel_token.clone();
        let task_handles = self.task_handles.clone();
        running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            let listener = match TcpListener::bind(format!("127.0.0.1:{}", port)).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!("Failed to bind local proxy on port {}: {:?}", port, e);
                    return;
                }
            };

            tracing::info!(
                "Local SOCKS5 & HTTP CONNECT proxy active on 127.0.0.1:{}",
                port
            );

            while running.load(Ordering::SeqCst) {
                let socket = tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    res = listener.accept() => {
                        match res {
                            Ok((s, _)) => s,
                            Err(_) => break,
                        }
                    }
                };

                let current = active_conns.load(Ordering::SeqCst);
                if current >= MAX_CONCURRENT_PROXY_CONNECTIONS {
                    tracing::warn!(
                        "Proxy connection cap exceeded ({}/{}), dropping connection",
                        current,
                        MAX_CONCURRENT_PROXY_CONNECTIONS
                    );
                    drop(socket);
                    continue;
                }

                active_conns.fetch_add(1, Ordering::SeqCst);
                let upstream = upstream.clone();
                let counter = active_conns.clone();
                let client_cancel = cancel_token.child_token();

                let handle = tokio::spawn(async move {
                    tokio::select! {
                        _ = client_cancel.cancelled() => {}
                        _ = handle_client(socket, upstream) => {}
                    }
                    counter.fetch_sub(1, Ordering::SeqCst);
                });

                if let Ok(mut lock) = task_handles.lock() {
                    lock.retain(|h| !h.is_finished());
                    lock.push(handle);
                }
            }
        })
    }

    pub async fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.cancel_token.cancel();
        let handles = if let Ok(mut lock) = self.task_handles.lock() {
            std::mem::take(&mut *lock)
        } else {
            Vec::new()
        };
        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            let _ = tokio::time::timeout(Duration::from_millis(500), handle).await;
        }
    }
}

pub async fn handle_client(
    mut client: tokio::net::TcpStream,
    upstream: Arc<H2UpstreamSession>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut initial_byte = [0u8; 1];
    let n = tokio::time::timeout(PROXY_HANDSHAKE_TIMEOUT, client.peek(&mut initial_byte)).await??;
    if n == 0 {
        return Ok(());
    }

    if initial_byte[0] == 0x05 {
        // SOCKS5
        handle_socks5(&mut client, upstream).await
    } else {
        // HTTP CONNECT / plain HTTP rejection
        handle_http_connect(&mut client, upstream).await
    }
}

pub async fn handle_socks5(
    client: &mut tokio::net::TcpStream,
    upstream: Arc<H2UpstreamSession>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let h2_stream_opt = tokio::time::timeout(PROXY_HANDSHAKE_TIMEOUT, async {
        // 1. Handshake
        let mut header = [0u8; 2];
        client.read_exact(&mut header).await?;
        if header[0] != 0x05 {
            return Err("Invalid SOCKS version".into());
        }

        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        client.read_exact(&mut methods).await?;

        // Check if NO AUTH (0x00) is supported
        if !methods.contains(&0x00) {
            client.write_all(&[0x05, 0xFF]).await?; // No acceptable methods
            return Err("No acceptable auth methods".into());
        }

        // Respond with NO AUTHENTICATION REQUIRED (0x00)
        client.write_all(&[0x05, 0x00]).await?;

        // 2. Request
        let mut req_header = [0u8; 4];
        client.read_exact(&mut req_header).await?;
        if req_header[0] != 0x05 {
            return Err("Invalid SOCKS version in request".into());
        }

        let cmd = req_header[1];
        let atyp = req_header[3];

        if cmd != 0x01 {
            // Only CONNECT (0x01) supported; reply 0x07 (Command not supported)
            client
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(None);
        }

        let target_host = match atyp {
            0x01 => {
                // IPv4
                let mut ip_bytes = [0u8; 4];
                client.read_exact(&mut ip_bytes).await?;
                Ipv4Addr::from(ip_bytes).to_string()
            }
            0x03 => {
                // Domain name
                let mut len_byte = [0u8; 1];
                client.read_exact(&mut len_byte).await?;
                let mut domain_bytes = vec![0u8; len_byte[0] as usize];
                client.read_exact(&mut domain_bytes).await?;
                String::from_utf8_lossy(&domain_bytes).to_string()
            }
            0x04 => {
                // IPv6
                let mut ip_bytes = [0u8; 16];
                client.read_exact(&mut ip_bytes).await?;
                Ipv6Addr::from(ip_bytes).to_string()
            }
            _ => {
                // Address type not supported (0x08)
                client
                    .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                return Ok(None);
            }
        };

        let mut port_bytes = [0u8; 2];
        client.read_exact(&mut port_bytes).await?;
        let target_port = u16::from_be_bytes(port_bytes);

        // 3. Connect via H2UpstreamSession
        match upstream.open_stream(&target_host, target_port).await {
            Ok(h2_stream) => {
                // SOCKS5 success reply (0x00)
                client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                Ok(Some(h2_stream))
            }
            Err(e) => {
                tracing::warn!(
                    "Upstream CONNECT failed for {}:{}: {:?}",
                    target_host,
                    target_port,
                    e
                );
                // Connection refused / Host unreachable (0x05)
                let _ = client
                    .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            }
        }
    })
    .await??;

    if let Some(mut h2_stream) = h2_stream_opt {
        copy_bidirectional_with_idle(client, &mut h2_stream, PROXY_IDLE_TIMEOUT).await?;
    }

    Ok(())
}

pub fn parse_http_connect_authority(authority: &str) -> Option<(String, u16)> {
    if authority.starts_with('[') {
        // IPv6 bracketed host: [::1]:port or [::1]
        let end_bracket = authority.find(']')?;
        let host = &authority[1..end_bracket];
        let port_part = &authority[end_bracket + 1..];
        let port = if let Some(stripped) = port_part.strip_prefix(':') {
            stripped.parse::<u16>().ok()?
        } else {
            443
        };
        Some((host.to_string(), port))
    } else if let Some(idx) = authority.rfind(':') {
        let host = &authority[..idx];
        let port = authority[idx + 1..].parse::<u16>().ok()?;
        Some((host.to_string(), port))
    } else {
        Some((authority.to_string(), 443))
    }
}

pub async fn handle_http_connect(
    client: &mut tokio::net::TcpStream,
    upstream: Arc<H2UpstreamSession>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let h2_stream_opt = tokio::time::timeout(PROXY_HANDSHAKE_TIMEOUT, async {
        let mut buf = Vec::with_capacity(1024);
        let mut temp = [0u8; 256];
        let mut found_header_end = false;

        // Read until \r\n\r\n (fragmentation support)
        while !found_header_end {
            if buf.len() > 8192 {
                let _ = client
                    .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                    .await;
                return Err(
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Header too large"))
                        as Box<dyn std::error::Error + Send + Sync>,
                );
            }
            let n = client.read(&mut temp).await?;
            if n == 0 {
                return Ok(None);
            }
            buf.extend_from_slice(&temp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                found_header_end = true;
            }
        }

        let req_str = String::from_utf8_lossy(&buf);
        let first_line = req_str.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.is_empty() {
            return Ok(None);
        }

        let method = parts[0].to_uppercase();

        if method == "CONNECT" {
            if parts.len() < 2 {
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                return Ok(None);
            }

            let authority = parts[1];
            let (host, port) = match parse_http_connect_authority(authority) {
                Some((h, p)) => (h, p),
                None => {
                    let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    return Ok(None);
                }
            };

            match upstream.open_stream(&host, port).await {
                Ok(h2_stream) => {
                    client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                    Ok(Some(h2_stream))
                }
                Err(e) => {
                    tracing::warn!("HTTP CONNECT failed for {}:{}: {:?}", host, port, e);
                    let _ = client
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        .await;
                    Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                }
            }
        } else {
            // Plain HTTP (GET, POST, etc.) is explicitly rejected per H8 specification
            tracing::info!("Rejecting unsupported plain HTTP proxy method: {}", method);
            let _ = client.write_all(b"HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nPlain HTTP proxying is disabled. Use HTTP CONNECT tunneling.\r\n").await;
            Ok(None)
        }
    })
    .await??;

    if let Some(mut h2_stream) = h2_stream_opt {
        copy_bidirectional_with_idle(client, &mut h2_stream, PROXY_IDLE_TIMEOUT).await?;
    }

    Ok(())
}
