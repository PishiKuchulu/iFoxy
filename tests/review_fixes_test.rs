//! Regression tests for the external-review fix wave (desktop 0.2.1):
//! H1 proxy bind errors, H4 control-API Content-Length, H6 packet
//! parser underflow, S3 Linux secret-store hardening, S6 journal
//! section-scoped cleanup.

use ifoxy_windows::vpn::packet::Ipv4Header;

// ---------------------------------------------------------------------------
// H6: Ipv4Header::parse must reject total_length < header length instead
// of underflowing the payload length computation.
// ---------------------------------------------------------------------------

fn packet_with(ihl_words: u8, total_length: u16, buf_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; buf_len];
    buf[0] = (4 << 4) | ihl_words;
    buf[2..4].copy_from_slice(&total_length.to_be_bytes());
    buf[8] = 64; // TTL
    buf[9] = 6; // TCP
    buf[12..16].copy_from_slice(&[10, 0, 0, 1]);
    buf[16..20].copy_from_slice(&[10, 0, 0, 2]);
    buf
}

#[test]
fn ipv4_parse_rejects_total_length_smaller_than_header() {
    // ihl = 20 bytes, total_length = 10: used to underflow and panic.
    let buf = packet_with(5, 10, 60);
    assert!(Ipv4Header::parse(&buf).is_none());
    // total_length = 0 is equally malformed.
    let buf = packet_with(5, 0, 60);
    assert!(Ipv4Header::parse(&buf).is_none());
    // total_length = 19 with a 20-byte buffer passes the old checks too.
    let buf = packet_with(5, 19, 20);
    assert!(Ipv4Header::parse(&buf).is_none());
}

#[test]
fn ipv4_parse_accepts_valid_packet_and_rejects_truncated() {
    let buf = packet_with(5, 40, 40);
    let (hdr, payload) = Ipv4Header::parse(&buf).expect("valid packet must parse");
    assert_eq!(hdr.total_length, 40);
    assert_eq!(payload.len(), 20);
    // Buffer shorter than total_length: rejected.
    let buf = packet_with(5, 60, 40);
    assert!(Ipv4Header::parse(&buf).is_none());
}

// ---------------------------------------------------------------------------
// H1: LocalProxyServer::start must surface a bind failure instead of
// logging it inside a detached task.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn local_proxy_start_reports_bind_conflict() {
    use ifoxy_windows::tunnel::h2_session::H2UpstreamSession;
    use ifoxy_windows::vpn::local_proxy::LocalProxyServer;
    use std::sync::Arc;

    let upstream = Arc::new(H2UpstreamSession::new_dummy("test_token"));
    let first = LocalProxyServer::new();
    // Port 0 is not usable for the system-proxy contract; grab a real
    // free port by binding a probe listener, then releasing it.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    first
        .start(port, upstream.clone())
        .await
        .expect("first bind must succeed");

    let second = LocalProxyServer::new();
    let err = second.start(port, upstream.clone()).await;
    assert!(
        err.is_err(),
        "second bind on the same port must return an error, not log-and-continue"
    );

    first.stop().await;
}

// ---------------------------------------------------------------------------
// H4: control-API error responses must carry a Content-Length that
// matches the body actually sent (42 != 46 and 17 != 19 truncated the
// bodies before this fix).
// ---------------------------------------------------------------------------

async fn raw_request(port: u16, req: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    resp
}

fn assert_content_length_matches(resp: &str) -> &str {
    let (head, body) = resp.split_once("\r\n\r\n").expect("response has header/body split");
    let declared: usize = head
        .lines()
        .find_map(|l| {
            let lower = l.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .map(|v| v.trim().to_string())
        })
        .map(|v| v.parse().expect("numeric content-length"))
        .expect("response declares Content-Length");
    assert_eq!(
        declared,
        body.len(),
        "declared Content-Length must equal the body byte count; head: {}",
        head
    );
    body
}

#[tokio::test]
async fn control_api_error_responses_have_correct_content_length() {
    use ifoxy_windows::control_api::run_hardened_ui_server;
    use ifoxy_windows::tauri_bridge::AppState;
    use std::sync::Arc;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = Arc::new(AppState::new());
    let token = "test-token-123".to_string();
    tokio::spawn(async move {
        let _ = run_hardened_ui_server(state, listener, token).await;
    });

    // Wrong Host header -> body "Invalid Host Header" (19 bytes).
    let resp = raw_request(
        port,
        "GET / HTTP/1.1\r\nHost: evil.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 400"));
    assert_eq!(assert_content_length_matches(&resp), "Invalid Host Header");

    // Missing Host header -> body "Missing Host Header" (19 bytes).
    let resp = raw_request(port, "GET / HTTP/1.0\r\nConnection: close\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 400"));
    assert_eq!(assert_content_length_matches(&resp), "Missing Host Header");

    // Wrong API token -> 46-byte JSON body, previously truncated at 42.
    let body = "{}";
    let req = format!(
        "POST /api/get_auth_state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-iFoxy-Token: wrong\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        port,
        body.len(),
        body
    );
    let resp = raw_request(port, &req).await;
    assert!(resp.starts_with("HTTP/1.1 401"));
    assert_eq!(
        assert_content_length_matches(&resp),
        "{\"success\":false,\"error\":\"Unauthorized token\"}"
    );
}

// ---------------------------------------------------------------------------
// S6: the shared journal clears section by section; the file survives
// until the last section is gone.
// ---------------------------------------------------------------------------

#[test]
fn journal_sections_clear_independently() {
    use ifoxy_windows::vpn::recovery_journal::RecoveryJournal;
    use ifoxy_windows::vpn::routing::RouteDefinition;
    use std::net::Ipv4Addr;

    let dir = std::env::temp_dir().join(format!("ifoxy-journal-test-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("recovery_journal.json");

    let mut j = RecoveryJournal::new(path.clone());
    j.record_route(
        RouteDefinition {
            destination: Ipv4Addr::new(0, 0, 0, 0),
            prefix_len: 1,
            gateway: Ipv4Addr::new(10, 254, 1, 1),
            metric: 1,
        },
        7,
    );
    j.record_wfp_filter(42);
    j.record_resolv_conf_backup("nameserver 192.168.1.1\n".to_string());
    j.flush_to_disk().unwrap();
    assert!(path.exists());

    j.clear_wfp_filters_for(&[42]);
    assert!(path.exists(), "routes + resolv sections must keep the journal");

    j.clear_routes_and_bypass();
    assert!(path.exists(), "resolv section must keep the journal");

    j.clear_resolv_conf_backup();
    assert!(!path.exists(), "journal file goes away with the last section");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// S3 (Linux): a corrupt key file is an error, never a silent key
// regeneration; clear() removes the key file too.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn linux_secret_store_corrupt_key_errors_and_clear_removes_key() {
    use ifoxy_windows::auth::secret_storage::{SecretStore, StoredSecrets};

    let dir = std::env::temp_dir().join(format!("ifoxy-secret-corrupt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &dir);
    let config_dir = dir.join("iFoxy");

    let store = SecretStore::new();
    let secrets = StoredSecrets {
        email: "user@example.com".to_string(),
        uid: "uid-1".to_string(),
        access_token: "access".to_string(),
        refresh_token: Some("refresh".to_string()),
        expires_at_epoch_sec: Some(1_900_000_000),
    };
    store.save(&secrets).unwrap();
    assert!(store.load().unwrap().is_some());
    assert!(config_dir.join("session.key").exists());

    // Corrupt the key: load must fail loudly instead of minting a new
    // key (which would silently orphan the stored session).
    std::fs::write(config_dir.join("session.key"), b"short").unwrap();
    assert!(
        store.load().is_err(),
        "corrupt key file must produce an error, not silent regeneration"
    );

    // clear() removes the key file as well as the session file.
    store.clear().unwrap();
    assert!(!config_dir.join("session.key").exists());
    assert!(!config_dir.join("session.enc").exists());

    let _ = std::fs::remove_dir_all(&dir);
}
