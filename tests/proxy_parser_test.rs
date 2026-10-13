use ifoxy_windows::vpn::local_proxy::parse_http_connect_authority;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn test_http_connect_authority_parsing() {
    // Normal host:port
    let (h, p) = parse_http_connect_authority("example.com:8080").unwrap();
    assert_eq!(h, "example.com");
    assert_eq!(p, 8080);

    // Default HTTPS port
    let (h, p) = parse_http_connect_authority("example.com").unwrap();
    assert_eq!(h, "example.com");
    assert_eq!(p, 443);

    // IPv6 bracketed with port
    let (h, p) = parse_http_connect_authority("[2001:db8::1]:8443").unwrap();
    assert_eq!(h, "2001:db8::1");
    assert_eq!(p, 8443);

    // IPv6 bracketed without port
    let (h, p) = parse_http_connect_authority("[::1]").unwrap();
    assert_eq!(h, "::1");
    assert_eq!(p, 443);
}

// Test SOCKS5 packet fragmentation & negotiation with a standalone mock server
#[tokio::test]
async fn test_socks5_fragmented_handshake_and_unsupported_cmd() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Read version & methods
        let mut header = [0u8; 2];
        socket.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x05);
        let mut methods = vec![0u8; header[1] as usize];
        socket.read_exact(&mut methods).await.unwrap();
        assert!(methods.contains(&0x00));

        // Reply 0x05 0x00
        socket.write_all(&[0x05, 0x00]).await.unwrap();

        // Read request
        let mut req_header = [0u8; 4];
        socket.read_exact(&mut req_header).await.unwrap();
        if req_header[1] != 0x01 {
            let mut rem = [0u8; 6];
            let _ = socket.read_exact(&mut rem).await;
            // Reply cmd not supported (0x07)
            socket
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let _ = socket.flush().await;
        }
    });

    let mut client = TcpStream::connect(addr).await.unwrap();

    // Send fragmented handshake (1 byte at a time)
    client.write_all(&[0x05]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    client.write_all(&[0x01]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    client.write_all(&[0x00]).await.unwrap();

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // Send BIND command (0x02, unsupported)
    client
        .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x07, "Must reply 0x07 Command Not Supported");

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_plain_http_proxy_explicit_rejection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);
        if req.starts_with("GET ") {
            socket
                .write_all(b"HTTP/1.1 501 Not Implemented\r\n\r\n")
                .await
                .unwrap();
        }
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();

    let mut reply = [0u8; 32];
    let n = client.read(&mut reply).await.unwrap();
    let s = String::from_utf8_lossy(&reply[..n]);
    assert!(
        s.contains("501 Not Implemented"),
        "Plain HTTP GET must be rejected with 501 Not Implemented"
    );

    server_task.await.unwrap();
}
