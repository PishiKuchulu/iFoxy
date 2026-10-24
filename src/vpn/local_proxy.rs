use crate::tunnel::h2_session::H2UpstreamSession;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Bind a TCP listener with SO_REUSEADDR set (Unix).
///
/// The local proxy restarts on the same port across connect/disconnect
/// cycles. On Linux, a just-closed accepted connection can sit in
/// TIME_WAIT with the listener's local address and block an immediate
/// rebind; Windows listeners get reuse semantics that mask this. Setting
/// the option on the listening socket before bind is what allows the
/// rebind, for this listener and for later binds over its TIME_WAIT
/// sockets. Non-Unix platforms keep tokio's plain bind.
pub async fn bind_listener(addr: &str) -> std::io::Result<TcpListener> {
    #[cfg(unix)]
    {
        use std::os::unix::io::FromRawFd;
        let parsed: std::net::SocketAddrV4 = match addr.parse() {
            Ok(v) => v,
            Err(_) => return TcpListener::bind(addr).await,
        };
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let cleanup = |fd: libc::c_int| -> std::io::Error {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            e
        };
        let one: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(cleanup(fd));
        }
        let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = parsed.port().to_be();
        sin.sin_addr = libc::in_addr {
            s_addr: u32::from(*parsed.ip()).to_be(),
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &sin as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(cleanup(fd));
        }
        if unsafe { libc::listen(fd, 128) } != 0 {
            return Err(cleanup(fd));
        }
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        std_listener.set_nonblocking(true)?;
        TcpListener::from_std(std_listener)
    }
    #[cfg(not(unix))]
    {
        TcpListener::bind(addr).await
    }
}

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
            // A completed write is activity too: a single write blocked
            // against a stalled peer must not let the idle timer kill a
            // live relay mid-transfer (external review, M3).
            let _ = tx_a.try_send(());
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
            let _ = tx_b.try_send(());
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
    accept_handle: Arc<std::sync::Mutex<Option<JoinHandle<()>>>>,
}

impl LocalProxyServer {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            cancel_token: CancellationToken::new(),
            task_handles: Arc::new(std::sync::Mutex::new(Vec::new())),
            accept_handle: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl Default for LocalProxyServer {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalProxyServer {
    /// Bind the listener FIRST and only then spawn the accept loop, so
    /// a bind failure (port already in use) is returned to the caller
    /// instead of being logged inside a detached task while the caller
    /// goes on to point the system proxy at a dead port and report
    /// Connected (external review, H1).
    pub async fn start(
        &self,
        port: u16,
        upstream: Arc<H2UpstreamSession>,
    ) -> std::io::Result<()> {
        let listener = bind_listener(&format!("127.0.0.1:{}", port)).await?;

        let running = self.running.clone();
        let active_conns = self.active_connections.clone();
        let cancel_token = self.cancel_token.clone();
        let task_handles = self.task_handles.clone();
        running.store(true, Ordering::SeqCst);

        let handle = tokio::spawn(async move {
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
        });

        if let Ok(mut lock) = self.accept_handle.lock() {
            *lock = Some(handle);
        }
        Ok(())
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
        // Join the accept task as well: stop() must guarantee the
        // listening socket is closed when it returns — previously that
        // was left to whichever tracker the caller had put the start
        // handle in, and an immediate rebind of the port could race the
        // accept task's final drop (observed on Linux under load).
        // The join is deliberately NOT timeout-capped: the accept loop
        // has no blocking sections and exits at its next poll once
        // cancelled, while a capped join can return early on a loaded
        // machine and leak exactly the race this join exists to close.
        let accept = if let Ok(mut lock) = self.accept_handle.lock() {
            lock.take()
        } else {
            None
        };
        if let Some(handle) = accept {
            handle.abort();
            let _ = handle.await;
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
    // The handshake timeout covers only the client-side greeting and
    // request bytes. It previously also wrapped the upstream CONNECT,
    // which conflated a slow edge with a stalled client — and made the
    // relay test fail deterministically under tokio's paused test clock,
    // whose auto-advance fires the timer while the upstream handshake is
    // still in flight. The upstream open has its own timeouts.
    enum SocksTarget {
        Connect(String, u16),
        /// A terminal reply was already sent (unsupported cmd/atyp).
        Done,
    }

    let parsed = tokio::time::timeout(PROXY_HANDSHAKE_TIMEOUT, async {
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
            return Ok(SocksTarget::Done);
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
                return Ok(SocksTarget::Done);
            }
        };

        let mut port_bytes = [0u8; 2];
        client.read_exact(&mut port_bytes).await?;
        let target_port = u16::from_be_bytes(port_bytes);

        Ok::<SocksTarget, Box<dyn std::error::Error + Send + Sync>>(SocksTarget::Connect(
            target_host,
            target_port,
        ))
    })
    .await??;

    // 3. Connect via H2UpstreamSession (outside the handshake timeout)
    let h2_stream_opt = match parsed {
        SocksTarget::Done => None,
        SocksTarget::Connect(target_host, target_port) => {
            match upstream.open_stream(&target_host, target_port).await {
                Ok(h2_stream) => {
                    // SOCKS5 success reply (0x00)
                    client
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                    Some(h2_stream)
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
                    return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                }
            }
        }
    };

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
        let mut header_end: Option<usize> = None;

        // Read until \r\n\r\n (fragmentation support)
        while header_end.is_none() {
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
            header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
        }
        let header_end = header_end.unwrap_or(buf.len());
        // Bytes that arrived in the same read as the header terminator
        // (e.g. a pipelined TLS ClientHello) belong to the tunnel: they
        // are forwarded upstream once the CONNECT succeeds instead of
        // being silently dropped with the header buffer (external
        // review, S2).
        let leftover: Vec<u8> = buf.drain(header_end..).collect();

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
                    Ok(Some((h2_stream, leftover)))
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

    if let Some((mut h2_stream, leftover)) = h2_stream_opt {
        if !leftover.is_empty() {
            h2_stream.write_all(&leftover).await?;
        }
        copy_bidirectional_with_idle(client, &mut h2_stream, PROXY_IDLE_TIMEOUT).await?;
    }

    Ok(())
}
