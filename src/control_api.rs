use crate::tauri_bridge::{
    AppState, APP_JS, IFOXY_BANNER_PNG, IFOXY_LOGO_PNG, IFOXY_SPLASH_PNG, IFOXY_WORDMARK_PNG,
    INDEX_HTML, STYLE_CSS,
};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub struct ControlApiConfig {
    pub port: u16,
    pub token: String,
    pub max_body_size: usize,
    pub read_timeout: Duration,
}

impl Default for ControlApiConfig {
    fn default() -> Self {
        use rand::RngCore;
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        Self {
            port: 0,
            token: hex::encode(token_bytes),
            max_body_size: 65536, // 64 KiB
            read_timeout: Duration::from_secs(5),
        }
    }
}

pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
}

pub async fn read_http_request<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    timeout_dur: Duration,
    max_body_size: usize,
) -> Result<HttpRequest, String> {
    tokio::time::timeout(timeout_dur, async {
        let mut buf = Vec::with_capacity(4096);
        let mut header_end = None;

        // 1. Read headers until \r\n\r\n
        let mut temp = [0u8; 1024];
        while header_end.is_none() {
            if buf.len() > 16384 {
                return Err("431 Request Header Fields Too Large".to_string());
            }
            let n = stream.read(&mut temp).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("Connection closed prematurely".to_string());
            }
            buf.extend_from_slice(&temp[..n]);

            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = Some(pos);
            }
        }

        let header_pos = header_end.unwrap();
        let header_bytes = &buf[..header_pos];
        let header_str = String::from_utf8_lossy(header_bytes);

        let mut lines = header_str.lines();
        let request_line = lines
            .next()
            .ok_or_else(|| "Empty request line".to_string())?;
        let req_parts: Vec<&str> = request_line.split_whitespace().collect();
        if req_parts.len() < 2 {
            return Err("Malformed request line".to_string());
        }

        let method = req_parts[0].to_uppercase();
        let path = req_parts[1].to_string();

        let mut headers = std::collections::HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }

        let content_length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        if content_length > max_body_size {
            return Err("413 Payload Too Large".to_string());
        }

        // Remaining bytes in buffer belong to body
        let body_start = header_pos + 4;
        let mut body = buf[body_start..].to_vec();

        // Read remaining body bytes if fragmented
        while body.len() < content_length {
            let needed = content_length - body.len();
            let to_read = needed.min(temp.len());
            let n = stream
                .read(&mut temp[..to_read])
                .await
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("Connection closed before complete body".to_string());
            }
            body.extend_from_slice(&temp[..n]);
        }

        Ok(HttpRequest {
            method,
            path,
            headers,
            body,
        })
    })
    .await
    .map_err(|_| "408 Request Timeout".to_string())?
}

pub const CSP_HEADER_VALUE: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http://127.0.0.1:* http://localhost:*; frame-ancestors 'none';";

pub async fn run_hardened_ui_server(
    state: Arc<AppState>,
    listener: TcpListener,
    expected_token: String,
) -> Result<(), std::io::Error> {
    let port = listener.local_addr()?.port();

    loop {
        let (mut socket, _) = listener.accept().await?;
        let state = state.clone();
        let expected_token = expected_token.clone();

        tokio::spawn(async move {
            let req = match read_http_request(&mut socket, Duration::from_secs(5), 65536).await {
                Ok(r) => r,
                Err(err_msg) => {
                    let (status, msg) = if err_msg.starts_with("413") {
                        ("413 Payload Too Large", "Payload Too Large")
                    } else if err_msg.starts_with("431") {
                        ("431 Request Header Fields Too Large", "Headers Too Large")
                    } else if err_msg.starts_with("408") {
                        ("408 Request Timeout", "Request Timeout")
                    } else {
                        ("400 Bad Request", "Bad Request")
                    };
                    let resp = format!(
                        "HTTP/1.1 {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        msg.len(),
                        msg
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }
            };

            // 1. Host header validation
            if let Some(host) = req.headers.get("host") {
                let valid_1 = format!("127.0.0.1:{}", port);
                let valid_2 = format!("localhost:{}", port);
                let valid_3 = "127.0.0.1";
                let valid_4 = "localhost";
                if host != &valid_1 && host != &valid_2 && host != valid_3 && host != valid_4 {
                    let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 17\r\nConnection: close\r\n\r\nInvalid Host Header";
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }
            } else {
                let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 17\r\nConnection: close\r\n\r\nMissing Host Header";
                let _ = socket.write_all(resp.as_bytes()).await;
                return;
            }

            // 2. Cross-origin validation
            if let Some(origin) = req.headers.get("origin") {
                let valid_orig_1 = format!("http://127.0.0.1:{}", port);
                let valid_orig_2 = format!("http://localhost:{}", port);
                let valid_orig_3 = "null"; // local file / webview origin
                if origin != &valid_orig_1 && origin != &valid_orig_2 && origin != valid_orig_3 {
                    let resp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 22\r\nConnection: close\r\n\r\nCross-Origin Forbidden";
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }
            }

            // Reject external Sec-Fetch-Site: cross-site
            if let Some(fetch_site) = req.headers.get("sec-fetch-site") {
                if fetch_site.eq_ignore_ascii_case("cross-site") {
                    let resp = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 22\r\nConnection: close\r\n\r\nCross-Origin Forbidden";
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }
            }

            // 3. Static Assets vs API
            if req.method == "OPTIONS" {
                let resp = format!(
                    "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: http://127.0.0.1:{}\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, X-iFoxy-Token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    port
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                return;
            }

            if req.path == "/" || req.path == "/index.html" {
                // Out-of-band token delivery (C2, R-10): Token is NEVER delivered over HTTP!
                // It is injected directly into WebView via wry with_initialization_script.
                let csp_tag = format!(
                    "<meta http-equiv=\"Content-Security-Policy\" content=\"{}\">",
                    CSP_HEADER_VALUE
                );
                let clean_html = INDEX_HTML.replace("<head>", &format!("<head>\n{}", csp_tag));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Security-Policy: {}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    CSP_HEADER_VALUE,
                    clean_html.len(),
                    clean_html
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            } else if req.path == "/style.css" {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/css; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    STYLE_CSS.len(),
                    STYLE_CSS
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            } else if req.path == "/app.js" {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    APP_JS.len(),
                    APP_JS
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            } else if req.path.starts_with("/assets/") {
                let asset: Option<&[u8]> = match req.path.as_str() {
                    "/assets/ifoxy_logo.png" => Some(IFOXY_LOGO_PNG),
                    "/assets/ifoxy_splash.png" => Some(IFOXY_SPLASH_PNG),
                    "/assets/ifoxy_banner.png" => Some(IFOXY_BANNER_PNG),
                    "/assets/ifoxy_wordmark.png" => Some(IFOXY_WORDMARK_PNG),
                    _ => None,
                };
                match asset {
                    Some(bytes) => {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            bytes.len()
                        );
                        let _ = socket.write_all(header.as_bytes()).await;
                        let _ = socket.write_all(bytes).await;
                    }
                    None => {
                        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = socket.write_all(resp.as_bytes()).await;
                    }
                }
            } else if req.path.starts_with("/api/") && req.method == "POST" {
                // 4. API Token Verification (Constant Time)
                let client_token = req
                    .headers
                    .get("x-ifoxy-token")
                    .map(|s| s.as_str())
                    .unwrap_or("");
                let is_valid = bool::from(client_token.as_bytes().ct_eq(expected_token.as_bytes()));
                if !is_valid {
                    let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 42\r\nConnection: close\r\n\r\n{\"success\":false,\"error\":\"Unauthorized token\"}";
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }

                let action = &req.path[5..];
                let payload: Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
                let result = state.dispatch_action(action, payload).await;
                let json_resp = serde_json::to_string(&result).unwrap_or_default();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: http://127.0.0.1:{}\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    port,
                    json_resp.len(),
                    json_resp
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            } else {
                let resp =
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });
    }
}
