use bytes::Bytes;
use ifoxy_windows::tunnel::h2_session::H2UpstreamSession;
use ifoxy_windows::vpn::local_proxy::handle_client;
use http::Response;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn start_mock_h2_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
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

#[tokio::test]
async fn test_socks5_relay_survives_30s_transfer() {
    tokio::time::pause();
    let (h2_addr, _h2_handle) = start_mock_h2_server().await;

    // Connect to mock H2 upstream and create H2UpstreamSession
    let h2_client_tcp = TcpStream::connect(h2_addr).await.unwrap();
    let (send_request, h2_conn) = h2::client::Builder::new()
        .handshake::<_, Bytes>(h2_client_tcp)
        .await
        .unwrap();

    tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    let session = Arc::new(H2UpstreamSession::from_send_request(
        send_request,
        "dummy_token",
    ));

    // Bind local proxy listener
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_session = session.clone();
    tokio::spawn(async move {
        if let Ok((client_sock, _)) = proxy_listener.accept().await {
            let _ = handle_client(client_sock, proxy_session).await;
        }
    });

    // Client connects to local proxy
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    // SOCKS5 greeting: [version 5, 1 method, method 0 (no auth)]
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // SOCKS5 connect request: CONNECT to domain example.com:443
    let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
    req.extend_from_slice(b"example.com");
    req.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&req).await.unwrap();
    tokio::task::yield_now().await;

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00, "SOCKS5 connect must succeed");

    // Immediate transfer before 10 seconds: send payload, receive echo
    client.write_all(b"hello_t0").await.unwrap();
    let mut echo_buf = [0u8; 8];
    client.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, b"hello_t0");

    // Now hold connection open and transfer across 30 seconds
    for sec in 1..=30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if sec == 15 || sec == 30 {
            let msg = format!("msg_at_{sec:02}");
            client.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; msg.len()];
            client.read_exact(&mut buf).await.unwrap_or_else(|_| {
                panic!("Relay must not be killed after 10s! Failed to read echo at {sec} seconds")
            });
            assert_eq!(buf, msg.as_bytes());
        }
    }
}

#[tokio::test]
async fn test_http_connect_relay_survives_30s_transfer() {
    tokio::time::pause();
    let (h2_addr, _h2_handle) = start_mock_h2_server().await;

    let h2_client_tcp = TcpStream::connect(h2_addr).await.unwrap();
    let (send_request, h2_conn) = h2::client::Builder::new()
        .handshake::<_, Bytes>(h2_client_tcp)
        .await
        .unwrap();

    tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    let session = Arc::new(H2UpstreamSession::from_send_request(
        send_request,
        "dummy_token",
    ));

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_session = session.clone();
    tokio::spawn(async move {
        if let Ok((client_sock, _)) = proxy_listener.accept().await {
            let _ = handle_client(client_sock, proxy_session).await;
        }
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();

    let mut reply = [0u8; 39];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"HTTP/1.1 200 Connection Established\r\n\r\n");

    // Immediate transfer at t=0
    client.write_all(b"hello_http_t0").await.unwrap();
    let mut echo_buf = [0u8; 13];
    client.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, b"hello_http_t0");

    // Transfer across 30 seconds
    for sec in 1..=30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if sec == 15 || sec == 30 {
            let msg = format!("http_msg_at_{sec:02}");
            client.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; msg.len()];
            client.read_exact(&mut buf).await.unwrap_or_else(|_| {
                panic!("HTTP CONNECT Relay must not be killed after 10s! Failed at {sec} seconds")
            });
            assert_eq!(buf, msg.as_bytes());
        }
    }
}

#[tokio::test]
async fn test_relay_idle_timeout_terminates_after_inactivity() {
    tokio::time::pause();
    let (h2_addr, _h2_handle) = start_mock_h2_server().await;

    let h2_client_tcp = TcpStream::connect(h2_addr).await.unwrap();
    let (send_request, h2_conn) = h2::client::Builder::new()
        .handshake::<_, Bytes>(h2_client_tcp)
        .await
        .unwrap();

    tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    let session = Arc::new(H2UpstreamSession::from_send_request(
        send_request,
        "dummy_token",
    ));

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_session = session.clone();
    tokio::spawn(async move {
        if let Ok((client_sock, _)) = proxy_listener.accept().await {
            let _ = handle_client(client_sock, proxy_session).await;
        }
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();

    let mut reply = [0u8; 39];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"HTTP/1.1 200 Connection Established\r\n\r\n");

    // Sleep 125 seconds without any activity (exceeds PROXY_IDLE_TIMEOUT of 120s)
    tokio::time::sleep(Duration::from_secs(125)).await;

    // After idle timeout, reading should return EOF (0 bytes) or error
    let mut buf = [0u8; 16];
    let res = client.read(&mut buf).await;
    match res {
        Ok(0) => {} // Clean EOF on idle termination
        Ok(_) => panic!("Connection should have been closed after idle timeout"),
        Err(_) => {} // Connection reset/aborted on idle termination
    }
}
