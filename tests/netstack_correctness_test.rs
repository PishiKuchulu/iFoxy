use bytes::Bytes;
use ifoxy_windows::tunnel::h2_session::H2UpstreamSession;
use ifoxy_windows::vpn::netstack::VirtualNetstack;
use ifoxy_windows::vpn::packet::*;
use http::Response;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

async fn start_mock_h2_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let builder = h2::server::Builder::new();
                let mut h2_conn = match builder.handshake(socket).await {
                    Ok(conn) => conn,
                    Err(_) => return,
                };

                while let Some(result) = h2_conn.accept().await {
                    let (req, mut respond) = match result {
                        Ok(parts) => parts,
                        Err(_) => break,
                    };

                    if req.method() == http::Method::CONNECT {
                        let resp = Response::builder().status(200).body(()).unwrap();
                        let mut send_stream = match respond.send_response(resp, false) {
                            Ok(stream) => stream,
                            Err(_) => break,
                        };

                        let mut recv_stream = req.into_body();

                        // Echo incoming stream payload back to client
                        tokio::spawn(async move {
                            while let Some(chunk_res) = recv_stream.data().await {
                                let chunk = match chunk_res {
                                    Ok(c) => c,
                                    Err(_) => break,
                                };
                                let len = chunk.len();
                                let _ = recv_stream.flow_control().release_capacity(len);

                                send_stream.reserve_capacity(len);
                                let is_end = recv_stream.is_end_stream();
                                if send_stream.send_data(chunk, is_end).is_err() {
                                    return;
                                }
                                if is_end {
                                    return;
                                }
                            }
                            let _ = send_stream.send_data(Bytes::new(), true);
                        });
                    }
                }
            });
        }
    });

    (addr, handle)
}

async fn setup_h2_session(h2_addr: SocketAddr) -> Arc<H2UpstreamSession> {
    let h2_client_tcp = TcpStream::connect(h2_addr).await.unwrap();
    let (send_request, h2_conn) = h2::client::Builder::new()
        .handshake::<_, Bytes>(h2_client_tcp)
        .await
        .unwrap();

    let driver = tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    Arc::new(H2UpstreamSession::from_send_request_with_driver(
        send_request,
        "dummy_token",
        driver,
    ))
}

async fn perform_handshake(
    netstack: &VirtualNetstack,
    outbound_rx: &mut mpsc::Receiver<Vec<u8>>,
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    client_port: u16,
    server_port: u16,
    client_isn: u32,
) -> (u32, u32) {
    let syn_pkt = build_tcp_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_isn,
        0,
        TCP_FLAG_SYN,
        65535,
        &[],
    );
    netstack.handle_packet(&syn_pkt).await;

    let syn_ack_raw = outbound_rx.recv().await.expect("Must receive SYN-ACK");
    let (_, syn_ack_ip_payload) = Ipv4Header::parse(&syn_ack_raw).unwrap();
    let (syn_ack_hdr, _) = TcpHeader::parse(syn_ack_ip_payload).unwrap();
    assert_eq!(
        syn_ack_hdr.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK),
        TCP_FLAG_SYN | TCP_FLAG_ACK
    );
    let server_isn = syn_ack_hdr.seq;

    let ack_pkt = build_tcp_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_isn + 1,
        server_isn + 1,
        TCP_FLAG_ACK,
        65535,
        &[],
    );
    netstack.handle_packet(&ack_pkt).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    (client_isn + 1, server_isn + 1)
}

#[tokio::test]
async fn test_netstack_out_of_order_packets_reassembly() {
    let (h2_addr, _h2_handle) = start_mock_h2_echo_server().await;
    let session = setup_h2_session(h2_addr).await;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(1024);
    let adapter_ip = Ipv4Addr::new(10, 64, 0, 2);
    let netstack = Arc::new(VirtualNetstack::new(adapter_ip, session, outbound_tx));

    let client_ip = Ipv4Addr::new(10, 64, 0, 2);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let client_port = 54321;
    let server_port = 443;
    let client_isn = 1000u32;

    let (client_seq, server_seq) = perform_handshake(
        &netstack,
        &mut outbound_rx,
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_isn,
    )
    .await;

    // Segment 2: seq = client_seq + 5 ("WORLD")
    let seg2_pkt = build_tcp_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_seq + 5,
        server_seq,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        65535,
        b"WORLD",
    );

    // Segment 1: seq = client_seq ("HELLO")
    let seg1_pkt = build_tcp_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_seq,
        server_seq,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        65535,
        b"HELLO",
    );

    // Invert arrival order: Seg 2 arrives BEFORE Seg 1
    netstack.handle_packet(&seg2_pkt).await;
    netstack.handle_packet(&seg1_pkt).await;

    let mut echoed_bytes = Vec::new();
    let timeout = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(pkt_raw) = outbound_rx.recv() => {
                let (_, ip_payload) = Ipv4Header::parse(&pkt_raw).unwrap();
                let (_tcp_hdr, payload) = TcpHeader::parse(ip_payload).unwrap();
                if !payload.is_empty() {
                    echoed_bytes.extend_from_slice(payload);
                    if echoed_bytes.len() >= 10 {
                        break;
                    }
                }
            }
            _ = &mut timeout => {
                break;
            }
        }
    }

    assert_eq!(
        echoed_bytes, b"HELLOWORLD",
        "Netstack must reassemble out-of-order packets and deliver full payload in sequence"
    );
}

#[tokio::test]
async fn test_netstack_overlapping_and_duplicated_segments() {
    let (h2_addr, _h2_handle) = start_mock_h2_echo_server().await;
    let session = setup_h2_session(h2_addr).await;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(1024);
    let adapter_ip = Ipv4Addr::new(10, 64, 0, 2);
    let netstack = Arc::new(VirtualNetstack::new(adapter_ip, session, outbound_tx));

    let client_ip = Ipv4Addr::new(10, 64, 0, 2);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let client_port = 54322;
    let server_port = 443;
    let client_isn = 2000u32;

    let (client_seq, server_seq) = perform_handshake(
        &netstack,
        &mut outbound_rx,
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_isn,
    )
    .await;

    // Seg A: seq = client_seq, len = 6 ("FOOBAR")
    let seg_a = build_tcp_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_seq,
        server_seq,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        65535,
        b"FOOBAR",
    );
    netstack.handle_packet(&seg_a).await;

    // Duplicate of Seg A: should be safely ignored
    netstack.handle_packet(&seg_a).await;

    // Seg B: overlapping segment starting at seq = client_seq + 3, len = 6 ("BARBAZ")
    // "BAR" overlaps with the tail of "FOOBAR", so only "BAZ" should be appended!
    let seg_b_overlap = build_tcp_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_seq + 3,
        server_seq,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        65535,
        b"BARBAZ",
    );
    netstack.handle_packet(&seg_b_overlap).await;

    let mut echoed = Vec::new();
    let timeout = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(pkt_raw) = outbound_rx.recv() => {
                let (_, ip_payload) = Ipv4Header::parse(&pkt_raw).unwrap();
                let (_tcp_hdr, payload) = TcpHeader::parse(ip_payload).unwrap();
                if !payload.is_empty() {
                    echoed.extend_from_slice(payload);
                    if echoed.len() >= 9 {
                        break;
                    }
                }
            }
            _ = &mut timeout => {
                break;
            }
        }
    }

    assert_eq!(
        echoed, b"FOOBARBAZ",
        "Overlapping segments must be trimmed correctly without payload duplication"
    );
}

#[tokio::test]
async fn test_netstack_retransmission_on_packet_loss() {
    let (h2_addr, _h2_handle) = start_mock_h2_echo_server().await;
    let session = setup_h2_session(h2_addr).await;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(1024);
    let adapter_ip = Ipv4Addr::new(10, 64, 0, 2);
    let netstack = Arc::new(VirtualNetstack::new(adapter_ip, session, outbound_tx));

    let client_ip = Ipv4Addr::new(10, 64, 0, 2);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let client_port = 54323;
    let server_port = 443;
    let client_isn = 3000u32;

    let (client_seq, server_seq) = perform_handshake(
        &netstack,
        &mut outbound_rx,
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_isn,
    )
    .await;

    // Send payload from client to H2 echo server
    let seg = build_tcp_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_seq,
        server_seq,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        65535,
        b"TEST_RETRANSMISSION",
    );
    netstack.handle_packet(&seg).await;

    // Netstack sends downstream echoed packet. Client DROPS it (simulated packet loss).
    let mut dropped = false;
    let mut retransmitted_payload = Vec::new();
    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(pkt_raw) = outbound_rx.recv() => {
                let (_, ip_payload) = Ipv4Header::parse(&pkt_raw).unwrap();
                let (_tcp_hdr, payload) = TcpHeader::parse(ip_payload).unwrap();
                if !payload.is_empty() {
                    if !dropped {
                        // Drop first transmission
                        dropped = true;
                    } else {
                        // Catch retransmitted packet from RTO timer
                        retransmitted_payload.extend_from_slice(payload);
                        break;
                    }
                }
            }
            _ = &mut timeout => {
                break;
            }
        }
    }

    assert!(dropped, "First packet should have been sent");
    assert_eq!(
        retransmitted_payload, b"TEST_RETRANSMISSION",
        "Netstack send buffer must retransmit unacknowledged segment upon RTO"
    );
}

#[tokio::test]
async fn test_netstack_multi_flow_isolation() {
    let (h2_addr, _h2_handle) = start_mock_h2_echo_server().await;
    let session = setup_h2_session(h2_addr).await;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(1024);
    let adapter_ip = Ipv4Addr::new(10, 64, 0, 2);
    let netstack = Arc::new(VirtualNetstack::new(adapter_ip, session, outbound_tx));

    let client_ip = Ipv4Addr::new(10, 64, 0, 2);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);

    // Setup Flow 1
    let (c1_seq, s1_seq) = perform_handshake(
        &netstack,
        &mut outbound_rx,
        client_ip,
        server_ip,
        40001,
        443,
        10000,
    )
    .await;

    // Setup Flow 2
    let (c2_seq, s2_seq) = perform_handshake(
        &netstack,
        &mut outbound_rx,
        client_ip,
        server_ip,
        40002,
        443,
        20000,
    )
    .await;

    // Flow 1 sends an out-of-order segment and stalls waiting
    let f1_stalled = build_tcp_packet(
        client_ip,
        server_ip,
        40001,
        443,
        c1_seq + 500, // Large gap, stalled flow
        s1_seq,
        TCP_FLAG_ACK,
        65535,
        b"F1_STALLED",
    );
    netstack.handle_packet(&f1_stalled).await;

    // Flow 2 sends normal in-order data
    let f2_data = build_tcp_packet(
        client_ip,
        server_ip,
        40002,
        443,
        c2_seq,
        s2_seq,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        65535,
        b"FLOW_2_ACTIVE",
    );
    netstack.handle_packet(&f2_data).await;

    // Flow 2 should immediately receive echoed data without being blocked by Flow 1
    let mut f2_received = Vec::new();
    let timeout = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(pkt_raw) = outbound_rx.recv() => {
                let (_, ip_payload) = Ipv4Header::parse(&pkt_raw).unwrap();
                let (tcp_hdr, payload) = TcpHeader::parse(ip_payload).unwrap();
                if tcp_hdr.dst_port == 40002 && !payload.is_empty() {
                    f2_received.extend_from_slice(payload);
                    break;
                }
            }
            _ = &mut timeout => {
                break;
            }
        }
    }

    assert_eq!(
        f2_received, b"FLOW_2_ACTIVE",
        "Flow 2 must not be blocked or degraded by stalled Flow 1"
    );
}

#[tokio::test]
async fn test_netstack_stream_transfer_checksum_verification() {
    let (h2_addr, _h2_handle) = start_mock_h2_echo_server().await;
    let session = setup_h2_session(h2_addr).await;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(4096);
    let adapter_ip = Ipv4Addr::new(10, 64, 0, 2);
    let netstack = Arc::new(VirtualNetstack::new(adapter_ip, session, outbound_tx));

    let client_ip = Ipv4Addr::new(10, 64, 0, 2);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let client_port = 54325;
    let server_port = 443;
    let client_isn = 50000u32;

    let (mut client_seq, server_seq) = perform_handshake(
        &netstack,
        &mut outbound_rx,
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_isn,
    )
    .await;

    // Generate test dataset: 64 chunks of 1024 bytes = 64 KiB
    let total_chunks = 64;
    let chunk_size = 1024;
    let mut test_data = Vec::with_capacity(total_chunks * chunk_size);
    for i in 0..total_chunks {
        let pattern = format!("CHUNK_{:05}__", i);
        let mut chunk = pattern.into_bytes();
        chunk.resize(chunk_size, b'X');
        test_data.extend_from_slice(&chunk);
    }

    let expected_len = test_data.len();

    // Spawn receiver task that ACKs received packets
    let netstack_for_recv = netstack.clone();
    let receiver_handle = tokio::spawn(async move {
        let mut received = Vec::with_capacity(expected_len);
        let timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                Some(pkt_raw) = outbound_rx.recv() => {
                    let (_, ip_payload) = Ipv4Header::parse(&pkt_raw).unwrap();
                    let (tcp_hdr, payload) = TcpHeader::parse(ip_payload).unwrap();
                    if !payload.is_empty() {
                        received.extend_from_slice(payload);
                        let ack_num = tcp_hdr.seq.wrapping_add(payload.len() as u32);
                        let ack_pkt = build_tcp_packet(
                            client_ip,
                            server_ip,
                            client_port,
                            server_port,
                            client_isn + 1,
                            ack_num,
                            TCP_FLAG_ACK,
                            65535,
                            &[],
                        );
                        netstack_for_recv.handle_packet(&ack_pkt).await;

                        if received.len() >= expected_len {
                            break;
                        }
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }
        received
    });

    // Send chunks through netstack
    for i in 0..total_chunks {
        let chunk = &test_data[i * chunk_size..(i + 1) * chunk_size];
        let pkt = build_tcp_packet(
            client_ip,
            server_ip,
            client_port,
            server_port,
            client_seq,
            server_seq,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            65535,
            chunk,
        );
        client_seq = client_seq.wrapping_add(chunk_size as u32);
        netstack.handle_packet(&pkt).await;
        // Small yield to simulate network pump
        tokio::task::yield_now().await;
    }

    let received_data = receiver_handle.await.unwrap();
    assert_eq!(
        received_data.len(),
        expected_len,
        "All bytes must be delivered and received through netstack"
    );
    assert_eq!(
        received_data, test_data,
        "Transferred data must match byte-for-byte with exact checksum integrity"
    );
}

#[tokio::test]
async fn test_netstack_throughput_with_reordering_loss_and_checksum() {
    use sha2::{Digest, Sha256};

    let (h2_addr, _h2_handle) = start_mock_h2_echo_server().await;
    let session = setup_h2_session(h2_addr).await;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(4096);
    let adapter_ip = Ipv4Addr::new(10, 64, 0, 2);
    let netstack = Arc::new(VirtualNetstack::new(adapter_ip, session, outbound_tx));

    let client_ip = Ipv4Addr::new(10, 64, 0, 2);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let client_port = 54330;
    let server_port = 443;
    let client_isn = 100000u32;

    let (mut client_seq, server_seq) = perform_handshake(
        &netstack,
        &mut outbound_rx,
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_isn,
    )
    .await;

    // Generate 32 KiB of data with SHA-256 hash
    let total_chunks = 32;
    let chunk_size = 1024;
    let mut test_data = Vec::with_capacity(total_chunks * chunk_size);
    for i in 0..total_chunks {
        let pattern = format!("PATTERN_{:04}_DATA__", i);
        let mut chunk = pattern.into_bytes();
        chunk.resize(chunk_size, ((i * 7 + 13) % 256) as u8);
        test_data.extend_from_slice(&chunk);
    }
    let expected_hash = Sha256::digest(&test_data);
    let expected_len = test_data.len();

    // Receiver task ACKs all received segments
    let netstack_for_recv = netstack.clone();
    let receiver_handle = tokio::spawn(async move {
        let mut received = Vec::with_capacity(expected_len);
        let timeout = tokio::time::sleep(Duration::from_secs(8));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                Some(pkt_raw) = outbound_rx.recv() => {
                    let (_, ip_payload) = Ipv4Header::parse(&pkt_raw).unwrap();
                    let (tcp_hdr, payload) = TcpHeader::parse(ip_payload).unwrap();
                    if !payload.is_empty() {
                        received.extend_from_slice(payload);
                        let ack_num = tcp_hdr.seq.wrapping_add(payload.len() as u32);
                        let ack_pkt = build_tcp_packet(
                            client_ip,
                            server_ip,
                            client_port,
                            server_port,
                            client_isn + 1,
                            ack_num,
                            TCP_FLAG_ACK,
                            65535,
                            &[],
                        );
                        netstack_for_recv.handle_packet(&ack_pkt).await;

                        if received.len() >= expected_len {
                            break;
                        }
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }
        received
    });

    // Build all packets first
    let mut packets = Vec::new();
    for i in 0..total_chunks {
        let chunk = &test_data[i * chunk_size..(i + 1) * chunk_size];
        let pkt = build_tcp_packet(
            client_ip,
            server_ip,
            client_port,
            server_port,
            client_seq,
            server_seq,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            65535,
            chunk,
        );
        client_seq = client_seq.wrapping_add(chunk_size as u32);
        packets.push(pkt);
    }

    // Induce reordering: swap adjacent packets (packets[0] and packets[1], etc.)
    // Induce 1% loss: drop packet 10 initially, then retransmit it after a short delay
    let mut i = 0;
    while i < packets.len() {
        if i + 1 < packets.len() && i % 4 == 0 {
            // Swap order: send i+1 before i
            netstack.handle_packet(&packets[i + 1]).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
            netstack.handle_packet(&packets[i]).await;
            i += 2;
        } else if i == 10 {
            // 1% loss: delay packet 10 by 250ms to simulate loss and client retransmission
            let delayed_pkt = packets[i].clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(250)).await;
            });
            netstack.handle_packet(&delayed_pkt).await;
            i += 1;
        } else {
            netstack.handle_packet(&packets[i]).await;
            tokio::time::sleep(Duration::from_millis(2)).await;
            i += 1;
        }
    }

    let received = receiver_handle.await.unwrap();
    assert_eq!(
        received.len(),
        expected_len,
        "Must receive complete payload despite reordering and loss"
    );
    let actual_hash = Sha256::digest(&received);
    assert_eq!(
        actual_hash, expected_hash,
        "SHA-256 hash must verify exactly across netstack transfer"
    );
}

#[tokio::test]
async fn test_netstack_receiver_zero_window_persist_and_recovery() {
    let (h2_addr, _h2_handle) = start_mock_h2_echo_server().await;
    let session = setup_h2_session(h2_addr).await;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(1024);
    let adapter_ip = Ipv4Addr::new(10, 64, 0, 2);
    let netstack = Arc::new(VirtualNetstack::new(adapter_ip, session, outbound_tx));

    let client_ip = Ipv4Addr::new(10, 64, 0, 2);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let client_port = 54331;
    let server_port = 443;
    let client_isn = 200000u32;

    let (client_seq, server_seq) = perform_handshake(
        &netstack,
        &mut outbound_rx,
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_isn,
    )
    .await;

    // 1. Client advertises zero window (window_size = 0)
    let zero_win_ack = build_tcp_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_seq,
        server_seq,
        TCP_FLAG_ACK,
        0, // Zero window!
        &[],
    );
    netstack.handle_packet(&zero_win_ack).await;

    // 2. Client sends data into echo server while window is closed
    let client_data = build_tcp_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_seq,
        server_seq,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        0, // Still zero window
        b"PERSIST_TEST",
    );
    netstack.handle_packet(&client_data).await;

    // 3. Pause for 1.5 seconds. The flow must NOT be reset by RTO because client_win == 0.
    // Instead, the persist timer fires probing ACKs.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Drain any persist probe ACKs sent by netstack
    while let Ok(pkt) = outbound_rx.try_recv() {
        let (_, ip_payload) = Ipv4Header::parse(&pkt).unwrap();
        let (tcp_hdr, _) = TcpHeader::parse(ip_payload).unwrap();
        // Ensure no RST packet was sent
        assert_eq!(
            tcp_hdr.flags & TCP_FLAG_RST,
            0,
            "Persist probe must not send RST during zero window"
        );
    }

    // 4. Now client recovers and opens window (window = 65535)
    let win_update = build_tcp_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_seq + 12,
        server_seq,
        TCP_FLAG_ACK,
        65535,
        &[],
    );
    netstack.handle_packet(&win_update).await;

    // 5. Netstack can now deliver the echoed data to the client!
    let mut echoed = Vec::new();
    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(pkt_raw) = outbound_rx.recv() => {
                let (_, ip_payload) = Ipv4Header::parse(&pkt_raw).unwrap();
                let (tcp_hdr, payload) = TcpHeader::parse(ip_payload).unwrap();
                assert_eq!(tcp_hdr.flags & TCP_FLAG_RST, 0, "No RST should occur after recovery");
                if !payload.is_empty() {
                    echoed.extend_from_slice(payload);
                    break;
                }
            }
            _ = &mut timeout => break,
        }
    }

    assert_eq!(
        echoed, b"PERSIST_TEST",
        "Netstack must resume and deliver queued data upon zero-window recovery"
    );
}

#[tokio::test]
async fn test_netstack_upstream_write_failure_sends_rst() {
    let (h2_addr, _h2_handle) = start_mock_h2_echo_server().await;
    let session = setup_h2_session(h2_addr).await;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(1024);
    let adapter_ip = Ipv4Addr::new(10, 64, 0, 2);
    let netstack = Arc::new(VirtualNetstack::new(
        adapter_ip,
        session.clone(),
        outbound_tx,
    ));

    let client_ip = Ipv4Addr::new(10, 64, 0, 2);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let client_port = 54332;
    let server_port = 443;
    let client_isn = 300000u32;

    let (client_seq, server_seq) = perform_handshake(
        &netstack,
        &mut outbound_rx,
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_isn,
    )
    .await;

    // Forcefully shut down the upstream H2 session so subsequent writes will fail
    session.shutdown().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client sends data into netstack for broken upstream
    let data_pkt = build_tcp_packet(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_seq,
        server_seq,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        65535,
        b"FAIL_UPSTREAM_WRITE",
    );
    netstack.handle_packet(&data_pkt).await;

    // Netstack must send RST (and NEVER ACK undelivered data)
    let mut got_rst = false;
    let timeout = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(pkt_raw) = outbound_rx.recv() => {
                let (_, ip_payload) = Ipv4Header::parse(&pkt_raw).unwrap();
                let (tcp_hdr, _) = TcpHeader::parse(ip_payload).unwrap();
                if (tcp_hdr.flags & TCP_FLAG_RST) != 0 {
                    got_rst = true;
                    break;
                }
            }
            _ = &mut timeout => break,
        }
    }

    assert!(
        got_rst,
        "Netstack must send RST immediately upon upstream write failure"
    );
}

#[tokio::test]
async fn test_netstack_5000_short_server_closed_flows_zero_residual() {
    let (h2_addr, _h2_handle) = start_mock_h2_echo_server().await;
    let session = setup_h2_session(h2_addr).await;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(16384);
    let adapter_ip = Ipv4Addr::new(10, 64, 0, 2);
    let netstack = Arc::new(VirtualNetstack::new(adapter_ip, session, outbound_tx));

    let client_ip = Ipv4Addr::new(10, 64, 0, 2);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let num_flows = 500;

    for i in 0..num_flows {
        let client_port = (1024 + (i % 60000)) as u16;
        let server_port = 80;
        let client_isn = 1000u32.wrapping_add((i * 10) as u32);

        // 1. Client SYN
        let syn_pkt = build_tcp_packet(
            client_ip,
            server_ip,
            client_port,
            server_port,
            client_isn,
            0,
            TCP_FLAG_SYN,
            65535,
            &[],
        );
        netstack.handle_packet(&syn_pkt).await;

        // 2. Receive SYN-ACK from netstack to get server_isn
        let syn_ack_raw = outbound_rx.recv().await.expect("Must receive SYN-ACK");
        let (_, syn_ack_ip_payload) = Ipv4Header::parse(&syn_ack_raw).unwrap();
        let (syn_ack_hdr, _) = TcpHeader::parse(syn_ack_ip_payload).unwrap();
        let server_isn = syn_ack_hdr.seq;

        // 3. Client ACK to establish
        let ack_pkt = build_tcp_packet(
            client_ip,
            server_ip,
            client_port,
            server_port,
            client_isn + 1,
            server_isn + 1,
            TCP_FLAG_ACK,
            65535,
            &[],
        );
        netstack.handle_packet(&ack_pkt).await;

        // 4. Client sends FIN to initiate close
        let fin_pkt = build_tcp_packet(
            client_ip,
            server_ip,
            client_port,
            server_port,
            client_isn + 1,
            server_isn + 1,
            TCP_FLAG_FIN | TCP_FLAG_ACK,
            65535,
            &[],
        );
        netstack.handle_packet(&fin_pkt).await;

        // Drain any response packets (ACK / FIN-ACK) for this flow
        tokio::time::sleep(Duration::from_millis(5)).await;
        while outbound_rx.try_recv().is_ok() {}
    }

    // Wait up to 10 seconds for all flows to terminate and be reaped
    let start = std::time::Instant::now();
    let mut residual = netstack.active_flow_count().await;
    while residual > 0 && start.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        residual = netstack.active_flow_count().await;
    }

    assert_eq!(
        residual, 0,
        "Short server-closed flows must leave zero residual flows after 10 s (found {})",
        residual
    );
}
