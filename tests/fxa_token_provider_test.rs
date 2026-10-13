use ifoxy_windows::auth::fxa_client::{FxaClient, OAuthTokens};
use ifoxy_windows::auth::secret_storage::SecretStore;
use ifoxy_windows::auth::token_provider::{FxaTokenProvider, TokenProvider};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct MockAuthServer {
    pub port: u16,
    pub refresh_count: Arc<AtomicU32>,
    pub destroy_count: Arc<AtomicU32>,
    _handle: tokio::task::JoinHandle<()>,
}

impl MockAuthServer {
    pub async fn spawn(behavior: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let refresh_count = Arc::new(AtomicU32::new(0));
        let destroy_count = Arc::new(AtomicU32::new(0));

        let rc = refresh_count.clone();
        let dc = destroy_count.clone();

        let handle = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("POST /oauth/token") {
                    rc.fetch_add(1, Ordering::SeqCst);
                    match behavior {
                        "success" => {
                            let resp_body = serde_json::json!({
                                "access_token": "refreshed_access_abc123",
                                "refresh_token": "rotated_refresh_def456",
                                "expires_in": 3600
                            })
                            .to_string();
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                resp_body.len(),
                                resp_body
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                        "perm_error_401" => {
                            let resp_body = serde_json::json!({
                                "error": "invalid_grant",
                                "message": "Refresh token expired or revoked"
                            })
                            .to_string();
                            let resp = format!(
                                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                resp_body.len(),
                                resp_body
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                        "transient_error_500" => {
                            let resp_body = "Internal Server Error";
                            let resp = format!(
                                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                resp_body.len(),
                                resp_body
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                        _ => {}
                    }
                } else if req.contains("POST /oauth/destroy") {
                    dc.fetch_add(1, Ordering::SeqCst);
                    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            }
        });

        Self {
            port,
            refresh_count,
            destroy_count,
            _handle: handle,
        }
    }
}

fn create_temp_secret_store() -> (Arc<SecretStore>, std::path::PathBuf) {
    let rand_id = rand::random::<u64>();
    let temp_path = std::env::temp_dir().join(format!("ifoxy_test_session_{}.enc", rand_id));
    let store = Arc::new(SecretStore::with_path(temp_path.clone()));
    (store, temp_path)
}

#[tokio::test]
async fn test_token_provider_returns_cached_token_when_valid() {
    let (store, path) = create_temp_secret_store();
    let fxa_client = Arc::new(FxaClient::new());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let initial = OAuthTokens {
        access_token: "valid_access_tok".into(),
        refresh_token: Some("valid_refresh_tok".into()),
        expires_at_epoch_seconds: now + 3600, // Valid for 1 hour
    };

    let provider = FxaTokenProvider::with_tokens(fxa_client, store.clone(), Some(initial));

    let tok = provider.get_access_token().await.unwrap();
    assert_eq!(tok, "valid_access_tok");

    let _ = store.clear();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn test_token_provider_refreshes_expired_token_automatically() {
    let server = MockAuthServer::spawn("success").await;
    let auth_url = format!("http://127.0.0.1:{}", server.port);

    let http_client = reqwest::Client::new();
    let fxa_client = Arc::new(FxaClient::with_client_and_server(http_client, &auth_url));

    let (store, path) = create_temp_secret_store();

    // Expired token (expires_at in past)
    let expired = OAuthTokens {
        access_token: "old_expired_tok".into(),
        refresh_token: Some("old_refresh_tok".into()),
        expires_at_epoch_seconds: 100,
    };

    let provider = FxaTokenProvider::with_tokens(fxa_client, store.clone(), Some(expired));

    // Requesting access token triggers auto-refresh
    let tok = provider.get_access_token().await.unwrap();
    assert_eq!(tok, "refreshed_access_abc123");
    assert_eq!(server.refresh_count.load(Ordering::SeqCst), 1);

    // Verify token was rotated and stored
    let current = provider.current_tokens().await.unwrap();
    assert_eq!(current.access_token, "refreshed_access_abc123");
    assert_eq!(
        current.refresh_token,
        Some("rotated_refresh_def456".to_string())
    );

    // Verify secret store has the rotated tokens saved
    let loaded = store.load().unwrap().unwrap();
    assert_eq!(loaded.access_token, "refreshed_access_abc123");
    assert_eq!(
        loaded.refresh_token,
        Some("rotated_refresh_def456".to_string())
    );

    let _ = store.clear();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn test_token_provider_handles_permanent_auth_failure_401_403() {
    let server = MockAuthServer::spawn("perm_error_401").await;
    let auth_url = format!("http://127.0.0.1:{}", server.port);

    let http_client = reqwest::Client::new();
    let fxa_client = Arc::new(FxaClient::with_client_and_server(http_client, &auth_url));

    let (store, path) = create_temp_secret_store();

    let expired = OAuthTokens {
        access_token: "invalid_tok".into(),
        refresh_token: Some("revoked_refresh_tok".into()),
        expires_at_epoch_seconds: 100,
    };

    let provider = FxaTokenProvider::with_tokens(fxa_client, store.clone(), Some(expired));

    let res = provider.get_access_token().await;
    assert!(res.is_err());
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("PermanentAuthError") || err_msg.contains("401"),
        "Expected PermanentAuthError, got: {}",
        err_msg
    );

    // Verify in-memory tokens and secret storage are wiped clean (C7, R-16)
    assert!(provider.current_tokens().await.is_none());
    assert!(store.load().unwrap().is_none());

    let _ = store.clear();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn test_token_provider_handles_transient_failure_with_fallback() {
    let server = MockAuthServer::spawn("transient_error_500").await;
    let auth_url = format!("http://127.0.0.1:{}", server.port);

    let http_client = reqwest::Client::new();
    let fxa_client = Arc::new(FxaClient::with_client_and_server(http_client, &auth_url));

    let (store, path) = create_temp_secret_store();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Token has 30 seconds left (< 60s triggers refresh, but still valid > now)
    let near_expiry = OAuthTokens {
        access_token: "still_valid_fallback_tok".into(),
        refresh_token: Some("some_refresh_tok".into()),
        expires_at_epoch_seconds: now + 30,
    };

    let provider = FxaTokenProvider::with_tokens(fxa_client, store.clone(), Some(near_expiry));

    // Refresh fails with 500, but fallback succeeds because token is still active
    let tok = provider.get_access_token().await.unwrap();
    assert_eq!(tok, "still_valid_fallback_tok");

    let _ = store.clear();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn test_token_provider_server_side_revocation_on_signout() {
    let server = MockAuthServer::spawn("success").await;
    let auth_url = format!("http://127.0.0.1:{}", server.port);

    let http_client = reqwest::Client::new();
    let fxa_client = Arc::new(FxaClient::with_client_and_server(http_client, &auth_url));

    let (store, path) = create_temp_secret_store();

    let tokens = OAuthTokens {
        access_token: "access_to_revoke".into(),
        refresh_token: Some("refresh_to_revoke".into()),
        expires_at_epoch_seconds: 9999999999,
    };

    let provider = FxaTokenProvider::with_tokens(fxa_client, store.clone(), Some(tokens));

    // Sign out revokes tokens on server
    provider.sign_out().await.unwrap();

    // Verify destroy endpoint was called twice (access token + refresh token)
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(server.destroy_count.load(Ordering::SeqCst), 2);

    // Verify local storage and memory cleared
    assert!(provider.current_tokens().await.is_none());
    assert!(store.load().unwrap().is_none());

    let _ = store.clear();
    let _ = std::fs::remove_file(&path);
}
