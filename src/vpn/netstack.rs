use crate::tunnel::h2_session::H2UpstreamSession;
use crate::vpn::packet::*;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};

pub const DEFAULT_MSS: u16 = 1380;
pub const DEFAULT_WINDOW_SIZE: u16 = 65535;
pub const MAX_FLOWS: usize = 4096;
pub const MAX_REASSEMBLY_BUF_PER_FLOW: usize = 262144; // 256 KiB
pub const MAX_IN_FLIGHT_BYTES_PER_FLOW: usize = 262144; // 256 KiB
pub const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
pub const RTO_DURATION: Duration = Duration::from_millis(200);
/// Upper bound for the exponentially backed-off retransmission timeout.
pub const MAX_RTO: Duration = Duration::from_secs(8);
/// Retransmissions of one segment before the flow is reset. With the
/// backoff above this is roughly 90 s, instead of the previous fixed
/// 200 ms x 12 (about 2.4 s) that killed any flow whose receiver paused
/// reading for a few seconds (S-3).
pub const MAX_RETRANSMITS: u32 = 15;
/// Idle limit for fully established connections. Half-open or closing
/// flows keep the shorter FLOW_IDLE_TIMEOUT. The old single 120 s limit
/// reset quiet long-lived connections such as SSH or IMAP IDLE (S-3).
pub const ESTABLISHED_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Maximum time to wait for the upstream CONNECT to be accepted (S-3).
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[inline]
pub fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[inline]
pub fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpConnState {
    SynReceived,
    Established,
    CloseWait,
    FinWait1,
    FinWait2,
    TimeWait,
    Closed,
}

pub enum FlowEvent {
    ClientPacket {
        tcp_hdr: TcpHeader,
        payload: Vec<u8>,
    },
    Shutdown,
}

struct UnackedSegment {
    seq: u32,
    data: Vec<u8>,
    sent_at: Instant,
    retransmit_count: u32,
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    response_payload: Vec<u8>,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct DnsCache {
    default_ttl: Duration,
    entries: HashMap<Vec<u8>, DnsCacheEntry>,
}

impl DnsCache {
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            default_ttl,
            entries: HashMap::new(),
        }
    }

    fn extract_key(query: &[u8]) -> Option<Vec<u8>> {
        if query.len() >= 12 {
            Some(query[2..].to_vec())
        } else {
            None
        }
    }

    pub fn lookup(&mut self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 2 {
            return None;
        }
        let key = Self::extract_key(query)?;
        let now = Instant::now();

        if let Some(entry) = self.entries.get(&key) {
            if entry.expires_at > now {
                let mut resp = entry.response_payload.clone();
                if resp.len() >= 2 {
                    resp[0] = query[0];
                    resp[1] = query[1];
                }
                return Some(resp);
            }
        }
        self.entries.remove(&key);
        None
    }

    pub fn insert(&mut self, query: &[u8], response: Vec<u8>) {
        if let Some(key) = Self::extract_key(query) {
            let expires_at = Instant::now() + self.default_ttl;
            if self.entries.len() >= 1024 {
                self.prune();
            }
            self.entries.insert(
                key,
                DnsCacheEntry {
                    response_payload: response,
                    expires_at,
                },
            );
        }
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
        if self.entries.len() >= 1024 {
            if let Some(k) = self.entries.keys().next().cloned() {
                self.entries.remove(&k);
            }
        }
    }
}

pub struct VirtualNetstack {
    adapter_ip: Ipv4Addr,
    upstream: Arc<H2UpstreamSession>,
    outbound_packet_tx: mpsc::Sender<Vec<u8>>,
    flows: Arc<RwLock<HashMap<FiveTuple, mpsc::Sender<FlowEvent>>>>,
    reap_tx: mpsc::Sender<FiveTuple>,
    running: Arc<AtomicBool>,
    dns_cache: Arc<tokio::sync::Mutex<DnsCache>>,
}

impl VirtualNetstack {
    pub fn new(
        adapter_ip: Ipv4Addr,
        upstream: Arc<H2UpstreamSession>,
        outbound_packet_tx: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let (reap_tx, mut reap_rx) = mpsc::channel::<FiveTuple>(1024);
        let flows = Arc::new(RwLock::new(HashMap::new()));
        let running = Arc::new(AtomicBool::new(true));
        let dns_cache = Arc::new(tokio::sync::Mutex::new(DnsCache::new(Duration::from_secs(
            60,
        ))));

        let flows_for_reaper = flows.clone();
        let running_for_reaper = running.clone();

        tokio::spawn(async move {
            while running_for_reaper.load(Ordering::SeqCst) {
                tokio::select! {
                    Some(tuple) = reap_rx.recv() => {
                        let mut lock = flows_for_reaper.write().await;
                        lock.remove(&tuple);
                    }
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        // Periodic health check
                    }
                }
            }
        });

        Self {
            adapter_ip,
            upstream,
            outbound_packet_tx,
            flows,
            reap_tx,
            running,
            dns_cache,
        }
    }

    pub fn start_reaper(&self) {
        // Background reaper is already started in constructor
    }

    pub async fn active_flow_count(&self) -> usize {
        self.flows.read().await.len()
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let flows = self.flows.clone();
        tokio::spawn(async move {
            let lock = flows.read().await;
            for tx in lock.values() {
                let _ = tx.send(FlowEvent::Shutdown).await;
            }
        });
    }

    pub async fn handle_packet(&self, packet: &[u8]) {
        let (ip_hdr, payload) = match Ipv4Header::parse(packet) {
            Some(res) => res,
            None => return,
        };

        match ip_hdr.protocol {
            PROTOCOL_ICMP => {
                self.handle_icmp(&ip_hdr, packet).await;
            }
            PROTOCOL_UDP => {
                self.handle_udp(&ip_hdr, payload, packet).await;
            }
            PROTOCOL_TCP => {
                self.handle_tcp(&ip_hdr, payload).await;
            }
            _ => {
                if let Some(rej) = build_icmp_port_unreachable(self.adapter_ip, packet) {
                    let _ = self.outbound_packet_tx.send(rej).await;
                }
            }
        }
    }

    async fn handle_icmp(&self, ip_hdr: &Ipv4Header, packet: &[u8]) {
        if ip_hdr.dst_ip == self.adapter_ip {
            if let Some(reply) = build_icmp_echo_reply(packet) {
                let _ = self.outbound_packet_tx.send(reply).await;
                return;
            }
        }
        if let Some(unreachable) = build_icmp_port_unreachable(self.adapter_ip, packet) {
            let _ = self.outbound_packet_tx.send(unreachable).await;
        }
    }

    async fn handle_udp(&self, ip_hdr: &Ipv4Header, payload: &[u8], full_packet: &[u8]) {
        if payload.len() < UDP_HEADER_LEN {
            return;
        }
        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);

        if dst_port == 53 {
            self.handle_dns_query(
                ip_hdr.src_ip,
                src_port,
                ip_hdr.dst_ip,
                &payload[UDP_HEADER_LEN..],
            )
            .await;
        } else if let Some(unreach) = build_icmp_port_unreachable(self.adapter_ip, full_packet) {
            let _ = self.outbound_packet_tx.send(unreach).await;
        }
    }

    async fn handle_dns_query(
        &self,
        client_ip: Ipv4Addr,
        client_port: u16,
        server_ip: Ipv4Addr,
        dns_payload: &[u8],
    ) {
        let cached = {
            let mut cache = self.dns_cache.lock().await;
            cache.lookup(dns_payload)
        };

        if let Some(resp_data) = cached {
            let udp_len = (8 + resp_data.len()) as u16;
            let ip_len = (20 + udp_len) as usize;
            let mut packet = vec![0u8; ip_len];

            let ip_hdr = Ipv4Header {
                ihl: 20,
                total_length: ip_len as u16,
                identification: 0x9999,
                flags_fragment: 0,
                ttl: 64,
                protocol: PROTOCOL_UDP,
                checksum: 0,
                src_ip: server_ip,
                dst_ip: client_ip,
            };
            ip_hdr.serialize_into(&mut packet[..20]);

            let udp_buf = &mut packet[20..];
            udp_buf[0..2].copy_from_slice(&53u16.to_be_bytes());
            udp_buf[2..4].copy_from_slice(&client_port.to_be_bytes());
            udp_buf[4..6].copy_from_slice(&udp_len.to_be_bytes());
            udp_buf[6..8].copy_from_slice(&[0, 0]);
            udp_buf[8..].copy_from_slice(&resp_data);

            let csum = calculate_transport_checksum(server_ip, client_ip, PROTOCOL_UDP, udp_buf);
            udp_buf[6..8].copy_from_slice(&csum.to_be_bytes());

            let _ = self.outbound_packet_tx.send(packet).await;
            return;
        }

        let upstream = self.upstream.clone();
        let outbound_tx = self.outbound_packet_tx.clone();
        let query_data = dns_payload.to_vec();
        let dns_cache = self.dns_cache.clone();

        tokio::spawn(async move {
            let dns_server = if server_ip.is_unspecified() || server_ip.is_loopback() {
                "1.1.1.1".to_string()
            } else {
                server_ip.to_string()
            };

            let res = tokio::time::timeout(Duration::from_secs(5), async {
                let tcp_res = async {
                    let mut stream = upstream
                        .open_stream(&dns_server, 53)
                        .await
                        .map_err(|e| format!("{:?}", e))?;
                    let len_prefix = (query_data.len() as u16).to_be_bytes();
                    stream
                        .write_all(&len_prefix)
                        .await
                        .map_err(|e| e.to_string())?;
                    stream
                        .write_all(&query_data)
                        .await
                        .map_err(|e| e.to_string())?;

                    let mut resp_len_buf = [0u8; 2];
                    stream
                        .read_exact(&mut resp_len_buf)
                        .await
                        .map_err(|e| e.to_string())?;
                    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
                    let mut resp_data = vec![0u8; resp_len];
                    stream
                        .read_exact(&mut resp_data)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok::<Vec<u8>, String>(resp_data)
                }
                .await;

                match tcp_res {
                    Ok(data) => Ok(data),
                    Err(e) => {
                        tracing::info!(
                            "Upstream CONNECT to 53 unavailable ({}), falling back to DoH over 443",
                            e
                        );
                        resolve_doh_over_connect(&upstream, &query_data).await
                    }
                }
            })
            .await;

            match res {
                Ok(Ok(resp_data)) => {
                    {
                        let mut cache = dns_cache.lock().await;
                        cache.insert(&query_data, resp_data.clone());
                    }

                    let udp_len = (8 + resp_data.len()) as u16;
                    let ip_len = (20 + udp_len) as usize;
                    let mut packet = vec![0u8; ip_len];

                    let ip_hdr = Ipv4Header {
                        ihl: 20,
                        total_length: ip_len as u16,
                        identification: 0x9999,
                        flags_fragment: 0,
                        ttl: 64,
                        protocol: PROTOCOL_UDP,
                        checksum: 0,
                        src_ip: server_ip,
                        dst_ip: client_ip,
                    };
                    ip_hdr.serialize_into(&mut packet[..20]);

                    let udp_buf = &mut packet[20..];
                    udp_buf[0..2].copy_from_slice(&53u16.to_be_bytes());
                    udp_buf[2..4].copy_from_slice(&client_port.to_be_bytes());
                    udp_buf[4..6].copy_from_slice(&udp_len.to_be_bytes());
                    udp_buf[6..8].copy_from_slice(&[0, 0]);
                    udp_buf[8..].copy_from_slice(&resp_data);

                    let csum =
                        calculate_transport_checksum(server_ip, client_ip, PROTOCOL_UDP, udp_buf);
                    udp_buf[6..8].copy_from_slice(&csum.to_be_bytes());

                    let _ = outbound_tx.send(packet).await;
                }
                Ok(Err(e)) => {
                    tracing::warn!("Failed to tunnel DNS query: {}", e);
                }
                Err(_) => {
                    tracing::warn!("DNS query to {} timed out after 4 seconds", dns_server);
                }
            }
        });
    }
}

async fn resolve_doh_over_connect(
    upstream: &H2UpstreamSession,
    query_data: &[u8],
) -> Result<Vec<u8>, String> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls_pki_types::ServerName::try_from("cloudflare-dns.com".to_string())
        .map_err(|e| format!("{:?}", e))?;

    let stream = upstream
        .open_stream("1.1.1.1", 443)
        .await
        .map_err(|e| format!("{:?}", e))?;
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("{:?}", e))?;

    let req_header = format!(
        "POST /dns-query HTTP/1.1\r\nHost: cloudflare-dns.com\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nAccept-Encoding: identity\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        query_data.len()
    );
    tls_stream
        .write_all(req_header.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    tls_stream
        .write_all(query_data)
        .await
        .map_err(|e| e.to_string())?;
    tls_stream.flush().await.map_err(|e| e.to_string())?;

    let mut resp_buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    loop {
        match tls_stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                resp_buf.extend_from_slice(&chunk[..n]);
                if resp_buf.len() > MAX_DOH_RESPONSE_BYTES {
                    return Err("DoH response too large".to_string());
                }
            }
            // Some servers close without a TLS close_notify; if we already
            // have data, let the HTTP parser decide whether it is complete.
            Err(_) if !resp_buf.is_empty() => break,
            Err(e) => return Err(e.to_string()),
        }
    }

    decode_doh_http_response(&resp_buf)
}

/// Upper bound for a DoH HTTP response (a DNS message is at most 64 KiB).
pub const MAX_DOH_RESPONSE_BYTES: usize = 70 * 1024;

/// Extracts the DNS message from a raw HTTP/1.1 DoH response. Handles both
/// `Content-Length` and `Transfer-Encoding: chunked` bodies. The previous
/// implementation returned everything after the headers, which corrupted the
/// DNS message whenever the server used chunked encoding.
pub fn decode_doh_http_response(resp: &[u8]) -> Result<Vec<u8>, String> {
    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Invalid HTTP response: missing header terminator".to_string())?;
    let header_str = String::from_utf8_lossy(&resp[..header_end]).to_string();
    let mut lines = header_str.lines();
    let status_line = lines.next().unwrap_or("");
    if status_line.split_whitespace().nth(1) != Some("200") {
        return Err(format!("DoH server returned non-200: {}", status_line));
    }

    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            } else if name == "content-length" {
                content_length = value.parse().ok();
            }
        }
    }

    let body = &resp[header_end + 4..];
    let out = if chunked {
        decode_chunked_body(body)?
    } else if let Some(n) = content_length {
        if body.len() < n {
            return Err("DoH response body truncated".to_string());
        }
        body[..n].to_vec()
    } else {
        body.to_vec()
    };

    if out.is_empty() {
        return Err("DoH server returned empty body".to_string());
    }
    Ok(out)
}

fn decode_chunked_body(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "Malformed chunked body".to_string())?;
        let size_line = std::str::from_utf8(&body[..line_end])
            .map_err(|_| "Malformed chunk size".to_string())?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size =
            usize::from_str_radix(size_hex, 16).map_err(|_| "Malformed chunk size".to_string())?;
        body = &body[line_end + 2..];
        if size == 0 {
            break;
        }
        if body.len() < 2 || size > body.len() - 2 {
            return Err("Truncated chunk".to_string());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
        if out.len() > MAX_DOH_RESPONSE_BYTES {
            return Err("DoH response too large".to_string());
        }
    }
    Ok(out)
}

impl VirtualNetstack {
    async fn handle_tcp(&self, ip_hdr: &Ipv4Header, payload: &[u8]) {
        let (tcp_hdr, tcp_payload) = match TcpHeader::parse(payload) {
            Some(res) => res,
            None => return,
        };

        let tuple = FiveTuple {
            src_ip: ip_hdr.src_ip,
            src_port: tcp_hdr.src_port,
            dst_ip: ip_hdr.dst_ip,
            dst_port: tcp_hdr.dst_port,
            protocol: PROTOCOL_TCP,
        };

        let is_syn = (tcp_hdr.flags & TCP_FLAG_SYN) != 0 && (tcp_hdr.flags & TCP_FLAG_ACK) == 0;

        if is_syn {
            let mut lock = self.flows.write().await;
            if let Some(existing_tx) = lock.get(&tuple) {
                let tx = existing_tx.clone();
                drop(lock);
                // try_send: never let one slow flow block the dispatcher
                // (and with it every other flow). A dropped packet is
                // recovered by normal TCP retransmission (S-3).
                let _ = tx.try_send(FlowEvent::ClientPacket {
                    tcp_hdr,
                    payload: tcp_payload.to_vec(),
                });
                return;
            }

            if lock.len() >= MAX_FLOWS {
                drop(lock);
                tracing::warn!("Max TCP flows reached ({}), dropping SYN", MAX_FLOWS);
                let rst = build_tcp_packet(
                    tuple.dst_ip,
                    tuple.src_ip,
                    tuple.dst_port,
                    tuple.src_port,
                    0,
                    tcp_hdr.seq.wrapping_add(1),
                    TCP_FLAG_RST | TCP_FLAG_ACK,
                    0,
                    &[],
                );
                let _ = self.outbound_packet_tx.send(rst).await;
                return;
            }

            let (flow_tx, flow_rx) = mpsc::channel::<FlowEvent>(256);
            lock.insert(tuple, flow_tx.clone());
            drop(lock);

            let actor = TcpFlowActor::new(
                tuple,
                self.upstream.clone(),
                self.outbound_packet_tx.clone(),
                self.reap_tx.clone(),
                tcp_hdr,
            );
            tokio::spawn(actor.run(flow_rx));
            return;
        }

        let flow_tx_opt = {
            let lock = self.flows.read().await;
            lock.get(&tuple).cloned()
        };

        match flow_tx_opt {
            Some(tx) => {
                // See the SYN branch above: non-blocking on purpose.
                let _ = tx.try_send(FlowEvent::ClientPacket {
                    tcp_hdr,
                    payload: tcp_payload.to_vec(),
                });
            }
            None => {
                if (tcp_hdr.flags & TCP_FLAG_RST) == 0 {
                    let rst = build_tcp_packet(
                        tuple.dst_ip,
                        tuple.src_ip,
                        tuple.dst_port,
                        tuple.src_port,
                        tcp_hdr.ack,
                        tcp_hdr.seq.wrapping_add(tcp_payload.len().max(1) as u32),
                        TCP_FLAG_RST | TCP_FLAG_ACK,
                        0,
                        &[],
                    );
                    let _ = self.outbound_packet_tx.send(rst).await;
                }
            }
        }
    }
}

struct TcpFlowActor {
    tuple: FiveTuple,
    upstream: Arc<H2UpstreamSession>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    reap_tx: mpsc::Sender<FiveTuple>,
    state: TcpConnState,
    _client_isn: u32,
    local_isn: u32,
    next_expected_client_seq: u32,
    next_local_seq: u32,
    last_acked_by_client: u32,
    last_client_ack: u32,
    client_win: u32,
    dup_ack_count: u32,
    last_activity: Instant,
    reassembly_queue: BTreeMap<u32, Vec<u8>>,
    inbound_buf_len: usize,
    unacked_segments: VecDeque<UnackedSegment>,
    client_fin_received: bool,
    h2_read_done: bool,
    last_probe: Instant,
}

impl TcpFlowActor {
    fn new(
        tuple: FiveTuple,
        upstream: Arc<H2UpstreamSession>,
        outbound_tx: mpsc::Sender<Vec<u8>>,
        reap_tx: mpsc::Sender<FiveTuple>,
        initial_syn_hdr: TcpHeader,
    ) -> Self {
        let client_isn = initial_syn_hdr.seq;
        let local_isn: u32 = rand::random();
        let next_expected = client_isn.wrapping_add(1);
        let next_local = local_isn.wrapping_add(1);

        Self {
            tuple,
            upstream,
            outbound_tx,
            reap_tx,
            state: TcpConnState::SynReceived,
            _client_isn: client_isn,
            local_isn,
            next_expected_client_seq: next_expected,
            next_local_seq: next_local,
            last_acked_by_client: local_isn,
            last_client_ack: local_isn,
            client_win: (initial_syn_hdr.window_size as u32).max(DEFAULT_MSS as u32),
            dup_ack_count: 0,
            last_activity: Instant::now(),
            reassembly_queue: BTreeMap::new(),
            inbound_buf_len: 0,
            unacked_segments: VecDeque::new(),
            client_fin_received: false,
            h2_read_done: false,
            last_probe: Instant::now(),
        }
    }

    async fn run(mut self, mut flow_rx: mpsc::Receiver<FlowEvent>) {
        // 1. Send SYN-ACK
        let syn_ack = build_tcp_syn_ack_packet(
            self.tuple.dst_ip,
            self.tuple.src_ip,
            self.tuple.dst_port,
            self.tuple.src_port,
            self.local_isn,
            self.next_expected_client_seq,
            DEFAULT_WINDOW_SIZE,
            DEFAULT_MSS,
        );
        let _ = self.outbound_tx.send(syn_ack).await;

        // 2. Connect to upstream H2
        let target_host = self.tuple.dst_ip.to_string();
        let target_port = self.tuple.dst_port;
        let open_res = tokio::time::timeout(
            UPSTREAM_CONNECT_TIMEOUT,
            self.upstream.open_stream(&target_host, target_port),
        )
        .await;
        let h2_stream = match open_res {
            Ok(Ok(s)) => Some(s),
            Ok(Err(e)) => {
                tracing::warn!(
                    "H2 bridge connect failed for {}:{}: {:?}",
                    target_host,
                    target_port,
                    e
                );
                None
            }
            Err(_) => {
                tracing::warn!(
                    "H2 bridge connect timed out for {}:{}",
                    target_host,
                    target_port
                );
                None
            }
        };
        let h2_stream = match h2_stream {
            Some(s) => s,
            None => {
                self.send_rst().await;
                let _ = self.reap_tx.send(self.tuple).await;
                return;
            }
        };

        let (mut h2_read, mut h2_write) = tokio::io::split(h2_stream);
        let mut h2_read_buf = vec![0u8; DEFAULT_MSS as usize];
        let mut rto_interval = tokio::time::interval(Duration::from_millis(100));
        let mut idle_interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            let can_read_h2 = !self.h2_read_done
                && (self.state == TcpConnState::Established
                    || self.state == TcpConnState::CloseWait)
                && self.in_flight_bytes() < self.effective_send_window();

            // Never read more from upstream than the client window allows.
            let room = self
                .effective_send_window()
                .saturating_sub(self.in_flight_bytes())
                .min(DEFAULT_MSS as usize)
                .max(1);

            tokio::select! {
                event = flow_rx.recv() => {
                    match event {
                        Some(FlowEvent::ClientPacket { tcp_hdr, payload }) => {
                            self.handle_client_packet(tcp_hdr, &payload, &mut h2_write).await;
                        }
                        Some(FlowEvent::Shutdown) | None => {
                            break;
                        }
                    }
                }

                res = h2_read.read(&mut h2_read_buf[..room]), if can_read_h2 => {
                    match res {
                        Ok(0) => {
                            self.h2_read_done = true;
                            self.handle_upstream_eof().await;
                        }
                        Ok(n) => {
                            self.handle_upstream_data(&h2_read_buf[..n]).await;
                        }
                        Err(_) => {
                            self.send_rst().await;
                            break;
                        }
                    }
                }

                _ = rto_interval.tick() => {
                    // Persist timer: while the client advertises a zero
                    // window, probe once a second so a lost window-update
                    // cannot stall the flow forever (S-3).
                    if self.client_win == 0 && self.last_probe.elapsed() >= Duration::from_secs(1) {
                        self.last_probe = Instant::now();
                        self.send_ack().await;
                    }
                    if self.check_and_handle_rto().await {
                        break;
                    }
                }

                _ = idle_interval.tick() => {
                    let limit = if self.state == TcpConnState::Established {
                        ESTABLISHED_IDLE_TIMEOUT
                    } else {
                        FLOW_IDLE_TIMEOUT
                    };
                    if self.last_activity.elapsed() >= limit {
                        break;
                    }
                }
            }

            if self.state == TcpConnState::Closed {
                break;
            }
        }

        let _ = self.reap_tx.send(self.tuple).await;
    }

    fn in_flight_bytes(&self) -> usize {
        self.next_local_seq.wrapping_sub(self.last_acked_by_client) as usize
    }

    fn effective_send_window(&self) -> usize {
        (self.client_win as usize).min(MAX_IN_FLIGHT_BYTES_PER_FLOW)
    }

    async fn handle_upstream_data(&mut self, data: &[u8]) {
        self.last_activity = Instant::now();
        let seq = self.next_local_seq;
        self.next_local_seq = self.next_local_seq.wrapping_add(data.len() as u32);

        self.unacked_segments.push_back(UnackedSegment {
            seq,
            data: data.to_vec(),
            sent_at: Instant::now(),
            retransmit_count: 0,
        });

        let pkt = build_tcp_packet(
            self.tuple.dst_ip,
            self.tuple.src_ip,
            self.tuple.dst_port,
            self.tuple.src_port,
            seq,
            self.next_expected_client_seq,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            DEFAULT_WINDOW_SIZE,
            data,
        );
        let _ = self.outbound_tx.send(pkt).await;
    }

    async fn handle_upstream_eof(&mut self) {
        self.last_activity = Instant::now();
        let fin_seq = self.next_local_seq;
        self.next_local_seq = self.next_local_seq.wrapping_add(1);

        if self.state == TcpConnState::CloseWait {
            self.state = TcpConnState::Closed;
        } else if self.state == TcpConnState::Established {
            self.state = TcpConnState::FinWait1;
        }

        let fin_pkt = build_tcp_packet(
            self.tuple.dst_ip,
            self.tuple.src_ip,
            self.tuple.dst_port,
            self.tuple.src_port,
            fin_seq,
            self.next_expected_client_seq,
            TCP_FLAG_FIN | TCP_FLAG_ACK,
            DEFAULT_WINDOW_SIZE,
            &[],
        );
        let _ = self.outbound_tx.send(fin_pkt).await;
    }

    async fn handle_client_packet<W: AsyncWriteExt + Unpin>(
        &mut self,
        tcp_hdr: TcpHeader,
        payload: &[u8],
        h2_write: &mut W,
    ) {
        self.last_activity = Instant::now();
        self.client_win = tcp_hdr.window_size as u32;

        if (tcp_hdr.flags & TCP_FLAG_RST) != 0 {
            self.state = TcpConnState::Closed;
            return;
        }

        // SYN deduplication
        if (tcp_hdr.flags & TCP_FLAG_SYN) != 0 && (tcp_hdr.flags & TCP_FLAG_ACK) == 0 {
            let syn_ack = build_tcp_syn_ack_packet(
                self.tuple.dst_ip,
                self.tuple.src_ip,
                self.tuple.dst_port,
                self.tuple.src_port,
                self.local_isn,
                self.next_expected_client_seq,
                DEFAULT_WINDOW_SIZE,
                DEFAULT_MSS,
            );
            let _ = self.outbound_tx.send(syn_ack).await;
            return;
        }

        if (tcp_hdr.flags & TCP_FLAG_ACK) != 0 {
            let ack_num = tcp_hdr.ack;
            if self.state == TcpConnState::SynReceived && ack_num == self.next_local_seq {
                self.state = TcpConnState::Established;
                self.last_acked_by_client = ack_num;
                self.last_client_ack = ack_num;
            } else if self.state == TcpConnState::FinWait1 && ack_num == self.next_local_seq {
                self.state = TcpConnState::FinWait2;
            }

            if seq_after(ack_num, self.last_client_ack) {
                self.last_client_ack = ack_num;
                self.last_acked_by_client = ack_num;
                self.dup_ack_count = 0;

                while let Some(front) = self.unacked_segments.front() {
                    let seg_end = front.seq.wrapping_add(front.data.len() as u32);
                    if seq_before(seg_end, ack_num) || seg_end == ack_num {
                        self.unacked_segments.pop_front();
                    } else {
                        break;
                    }
                }
            } else if ack_num == self.last_client_ack && !self.unacked_segments.is_empty() {
                self.dup_ack_count += 1;
                if self.dup_ack_count == 3 {
                    // Fast retransmit on 3 duplicate ACKs
                    if let Some(first) = self.unacked_segments.front_mut() {
                        first.sent_at = Instant::now();
                        first.retransmit_count += 1;
                        let pkt = build_tcp_packet(
                            self.tuple.dst_ip,
                            self.tuple.src_ip,
                            self.tuple.dst_port,
                            self.tuple.src_port,
                            first.seq,
                            self.next_expected_client_seq,
                            TCP_FLAG_ACK | TCP_FLAG_PSH,
                            DEFAULT_WINDOW_SIZE,
                            &first.data,
                        );
                        let _ = self.outbound_tx.send(pkt).await;
                    }
                }
            }
        }

        // Handle inbound data payload
        if !payload.is_empty()
            && (self.state == TcpConnState::Established
                || self.state == TcpConnState::SynReceived
                || self.state == TcpConnState::FinWait1
                || self.state == TcpConnState::FinWait2)
        {
            let seq = tcp_hdr.seq;
            let len = payload.len() as u32;
            let seg_end = seq.wrapping_add(len);

            if seq_before(seg_end, self.next_expected_client_seq)
                || seg_end == self.next_expected_client_seq
            {
                // Pure duplicate segment: already consumed
                self.send_ack().await;
            } else if seq_before(seq, self.next_expected_client_seq) {
                // Overlap: trim duplicate prefix
                let trim = self.next_expected_client_seq.wrapping_sub(seq) as usize;
                let valid = &payload[trim..];
                if !self.forward_to_upstream(h2_write, valid).await {
                    return;
                }
                self.next_expected_client_seq = self
                    .next_expected_client_seq
                    .wrapping_add(valid.len() as u32);
                if !self.drain_reassembly_queue(h2_write).await {
                    return;
                }
                self.send_ack().await;
            } else if seq == self.next_expected_client_seq {
                // In-sequence arrival
                if !self.forward_to_upstream(h2_write, payload).await {
                    return;
                }
                self.next_expected_client_seq = self.next_expected_client_seq.wrapping_add(len);
                if !self.drain_reassembly_queue(h2_write).await {
                    return;
                }
                self.send_ack().await;
            } else {
                // Out-of-order segment
                if self.inbound_buf_len + payload.len() <= MAX_REASSEMBLY_BUF_PER_FLOW {
                    self.inbound_buf_len += payload.len();
                    self.reassembly_queue.insert(seq, payload.to_vec());
                }
                // Send duplicate ACK prompting fast retransmit
                self.send_ack().await;
            }
        }

        // Handle client FIN
        if (tcp_hdr.flags & TCP_FLAG_FIN) != 0 && !self.client_fin_received {
            self.client_fin_received = true;
            self.next_expected_client_seq = self.next_expected_client_seq.wrapping_add(1);
            let _ = h2_write.shutdown().await;

            if self.state == TcpConnState::Established {
                self.state = TcpConnState::CloseWait;
            } else if self.state == TcpConnState::FinWait1 || self.state == TcpConnState::FinWait2 {
                // Both directions are finished. This is a proxy, not an
                // endpoint that must absorb stray segments, so close the
                // flow now instead of lingering until the idle reaper.
                // Server-closed connections used to sit around for 120 s
                // each and exhaust MAX_FLOWS under load (S-3).
                self.state = TcpConnState::Closed;
            }

            self.send_ack().await;
        }
    }

    async fn drain_reassembly_queue<W: AsyncWriteExt + Unpin>(&mut self, h2_write: &mut W) -> bool {
        while let Some((&queued_seq, _)) = self.reassembly_queue.iter().next() {
            let queued_data = self.reassembly_queue.remove(&queued_seq).unwrap();
            self.inbound_buf_len = self.inbound_buf_len.saturating_sub(queued_data.len());
            let queued_len = queued_data.len() as u32;
            let queued_end = queued_seq.wrapping_add(queued_len);

            if seq_before(queued_end, self.next_expected_client_seq)
                || queued_end == self.next_expected_client_seq
            {
                continue;
            }

            if seq_before(queued_seq, self.next_expected_client_seq) {
                let trim = self.next_expected_client_seq.wrapping_sub(queued_seq) as usize;
                let valid = &queued_data[trim..];
                if !self.forward_to_upstream(h2_write, valid).await {
                    return false;
                }
                self.next_expected_client_seq = self
                    .next_expected_client_seq
                    .wrapping_add(valid.len() as u32);
            } else if queued_seq == self.next_expected_client_seq {
                if !self.forward_to_upstream(h2_write, &queued_data).await {
                    return false;
                }
                self.next_expected_client_seq =
                    self.next_expected_client_seq.wrapping_add(queued_len);
            } else {
                // Gap exists
                self.inbound_buf_len += queued_data.len();
                self.reassembly_queue.insert(queued_seq, queued_data);
                break;
            }
        }
        true
    }

    /// Writes client data to the upstream stream. On failure the client is
    /// reset instead of being ACKed for bytes that were never delivered:
    /// the previous code ignored the write error and still advanced
    /// `next_expected_client_seq` and ACKed, silently losing data (S-3).
    async fn forward_to_upstream<W: AsyncWriteExt + Unpin>(
        &mut self,
        h2_write: &mut W,
        data: &[u8],
    ) -> bool {
        match h2_write.write_all(data).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("Upstream write failed, resetting flow: {:?}", e);
                self.send_rst().await;
                self.state = TcpConnState::Closed;
                false
            }
        }
    }

    async fn send_ack(&self) {
        let ack_pkt = build_tcp_packet(
            self.tuple.dst_ip,
            self.tuple.src_ip,
            self.tuple.dst_port,
            self.tuple.src_port,
            self.next_local_seq,
            self.next_expected_client_seq,
            TCP_FLAG_ACK,
            DEFAULT_WINDOW_SIZE,
            &[],
        );
        let _ = self.outbound_tx.send(ack_pkt).await;
    }

    async fn send_rst(&self) {
        let rst = build_tcp_packet(
            self.tuple.dst_ip,
            self.tuple.src_ip,
            self.tuple.dst_port,
            self.tuple.src_port,
            self.next_local_seq,
            self.next_expected_client_seq,
            TCP_FLAG_RST | TCP_FLAG_ACK,
            0,
            &[],
        );
        let _ = self.outbound_tx.send(rst).await;
    }

    async fn check_and_handle_rto(&mut self) -> bool {
        // While the client window is zero the persist timer drives probing;
        // retransmitting into a closed window and counting those attempts
        // toward the give-up limit is what used to reset paused receivers.
        if self.client_win == 0 {
            return false;
        }
        if let Some(first) = self.unacked_segments.front_mut() {
            let backoff = 1u32 << first.retransmit_count.min(6);
            let rto = (RTO_DURATION * backoff).min(MAX_RTO);
            if first.sent_at.elapsed() >= rto {
                first.sent_at = Instant::now();
                first.retransmit_count += 1;
                if first.retransmit_count > MAX_RETRANSMITS {
                    self.send_rst().await;
                    return true;
                }
                let pkt = build_tcp_packet(
                    self.tuple.dst_ip,
                    self.tuple.src_ip,
                    self.tuple.dst_port,
                    self.tuple.src_port,
                    first.seq,
                    self.next_expected_client_seq,
                    TCP_FLAG_ACK | TCP_FLAG_PSH,
                    DEFAULT_WINDOW_SIZE,
                    &first.data,
                );
                let _ = self.outbound_tx.send(pkt).await;
            }
        }
        false
    }
}
