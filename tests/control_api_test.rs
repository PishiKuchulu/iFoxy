use ifoxy_windows::control_api::{run_hardened_ui_server, CSP_HEADER_VALUE};
use ifoxy_windows::tauri_bridge::AppState;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_test_server() -> (u16, String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let token = "test_secret_token_1234567890abcdef".to_string();
    let state = Arc::new(AppState::new());
    let token_clone = token.clone();

    let handle = tokio::spawn(async move {
        let _ = run_hardened_ui_server(state, listener, token_clone).await;
    });

    (port, token, handle)
}

#[tokio::test]
async fn test_control_api_csp_present_on_index() {
    let (port, _token, _handle) = spawn_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    let req = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        port
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();

    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(
        resp.contains("Content-Security-Policy:"),
        "Response MUST contain Content-Security-Policy header"
    );
    assert!(
        resp.contains(CSP_HEADER_VALUE),
        "Response MUST contain exact strict CSP header value"
    );
    assert!(resp.contains("X-Content-Type-Options: nosniff"));
    assert!(resp.contains("X-Frame-Options: DENY"));
}

#[tokio::test]
async fn test_control_api_serves_all_brand_png_assets() {
    // All four iFoxy brand PNGs must be served with image/png and valid PNG bytes.
    for path in [
        "/assets/ifoxy_logo.png",
        "/assets/ifoxy_splash.png",
        "/assets/ifoxy_banner.png",
        "/assets/ifoxy_wordmark.png",
    ] {
        let (port, _token, _handle) = spawn_test_server().await;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            path, port
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        let sep = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header/body separator");
        let headers = String::from_utf8_lossy(&resp[..sep]);
        let body = &resp[sep + 4..];
        assert!(
            headers.starts_with("HTTP/1.1 200 OK"),
            "{} must return 200 OK",
            path
        );
        assert!(
            headers.contains("Content-Type: image/png"),
            "{} must be served as image/png",
            path
        );
        assert!(
            body.len() > 8 && body.starts_with(b"\x89PNG"),
            "{} must contain real PNG bytes",
            path
        );
    }
}

#[tokio::test]
async fn test_control_api_wrong_host_rejected() {
    let (port, _token, _handle) = spawn_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    let req = "GET / HTTP/1.1\r\nHost: evil.attacker.com\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();

    assert!(
        resp.starts_with("HTTP/1.1 400 Bad Request"),
        "Wrong Host header must be rejected with 400 Bad Request"
    );
}

#[tokio::test]
async fn test_control_api_cross_origin_rejected() {
    let (port, token, _handle) = spawn_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    let body = "{}";
    let req = format!(
        "POST /api/get_auth_state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: https://evil.com\r\nX-iFoxy-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        port, token, body.len(), body
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();

    assert!(
        resp.starts_with("HTTP/1.1 403 Forbidden"),
        "Cross-origin request MUST be rejected with 403 Forbidden"
    );
}

#[tokio::test]
async fn test_control_api_missing_or_incorrect_token_rejected() {
    let (port, _token, _handle) = spawn_test_server().await;

    // 1. Missing token
    {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let body = "{}";
        let req = format!(
            "POST /api/get_auth_state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, body.len(), body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"));
    }

    // 2. Incorrect token
    {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let body = "{}";
        let req = format!(
            "POST /api/get_auth_state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-iFoxy-Token: WRONG_TOKEN_VALUE\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, body.len(), body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"));
    }
}

#[tokio::test]
async fn test_control_api_fragmented_request_parsed() {
    let (port, token, _handle) = spawn_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    let body = "{}";
    let part1 = format!(
        "POST /api/get_auth_state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n",
        port
    );
    let part2 = format!(
        "X-iFoxy-Token: {}\r\nContent-Length: {}\r\n",
        token,
        body.len()
    );
    let part3 = format!("Connection: close\r\n\r\n{}", body);

    // Send chunks with small delay to test fragmented stream reassembly
    stream.write_all(part1.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    stream.write_all(part2.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    stream.write_all(part3.as_bytes()).await.unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();

    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "Fragmented valid request must be assembled and return 200 OK: got {}",
        resp
    );
}

#[tokio::test]
async fn test_control_api_oversized_body_rejected() {
    let (port, token, _handle) = spawn_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Advertise 100 KiB body (above 64 KiB limit)
    let req = format!(
        "POST /api/get_auth_state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-iFoxy-Token: {}\r\nContent-Length: 102400\r\nConnection: close\r\n\r\n",
        port, token
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();

    assert!(
        resp.starts_with("HTTP/1.1 413 Payload Too Large"),
        "Oversized request must be rejected with 413: got {}",
        resp
    );
}

#[tokio::test]
async fn test_control_api_slow_client_times_out() {
    let (port, _token, _handle) = spawn_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Send incomplete request headers and stall
    stream
        .write_all(b"POST /api/get_auth_state HTTP/1.1\r\n")
        .await
        .unwrap();

    // Server timeout is 5s. Wait for server to time out and close/respond with 408
    let mut buf = [0u8; 512];
    let start = std::time::Instant::now();
    let res = stream.read(&mut buf).await;
    let elapsed = start.elapsed();

    // Either read error/EOF or 408 returned
    assert!(
        elapsed >= Duration::from_secs(4),
        "Timeout must take at least close to configured timeout (5s)"
    );
    match res {
        Ok(n) if n > 0 => {
            let s = String::from_utf8_lossy(&buf[..n]);
            assert!(s.contains("408 Request Timeout"));
        }
        _ => {
            // Connection closed by timeout
        }
    }
}

#[tokio::test]
async fn test_second_local_process_cannot_obtain_control_token_via_http() {
    let (port, token, _handle) = spawn_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    let req = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        port
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();

    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    // Under C2/R-10, control token is NEVER delivered over HTTP in index.html!
    // A second local process connecting to the port cannot extract any secret token.
    assert!(
        !resp.contains(&token),
        "CRITICAL LEAK: Control API token MUST NOT be exposed in HTTP response body to localhost!"
    );
}
