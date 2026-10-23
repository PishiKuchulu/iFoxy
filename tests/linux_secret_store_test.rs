#![cfg(target_os = "linux")]
//! Round-trip test for the Linux secret store (ChaCha20-Poly1305 with a
//! per-user 0600 key file — the DPAPI user-scope equivalent). Runs
//! against a throwaway XDG_CONFIG_HOME so it never touches real state.

use ifoxy_windows::auth::secret_storage::{SecretStore, StoredSecrets};
use std::os::unix::fs::PermissionsExt;

#[test]
fn linux_secret_store_round_trip() {
    let dir = std::env::temp_dir().join(format!("ifoxy-secret-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &dir);

    let store = SecretStore::new();
    assert!(store.load().unwrap().is_none(), "fresh store must be empty");

    let secrets = StoredSecrets {
        email: "user@example.com".to_string(),
        uid: "uid-123".to_string(),
        access_token: "access-token-value".to_string(),
        refresh_token: Some("refresh-token-value".to_string()),
        expires_at_epoch_sec: Some(1_900_000_000),
    };
    store.save(&secrets).unwrap();

    // Ciphertext on disk is the ENC2 AEAD format, never plaintext JSON.
    let config_dir = dir.join("iFoxy");
    let raw = std::fs::read(config_dir.join("session.enc")).unwrap();
    assert!(raw.starts_with(b"ENC2:"), "unexpected store format");
    assert!(
        !String::from_utf8_lossy(&raw).contains("access-token-value"),
        "plaintext token leaked into the store file"
    );

    // Key file exists alongside with owner-only permissions.
    let key_meta = std::fs::metadata(config_dir.join("session.key")).unwrap();
    assert_eq!(key_meta.permissions().mode() & 0o777, 0o600);

    let loaded = store.load().unwrap().expect("saved secrets must load");
    assert_eq!(loaded.email, secrets.email);
    assert_eq!(loaded.access_token, secrets.access_token);
    assert_eq!(loaded.refresh_token.as_deref(), Some("refresh-token-value"));
    assert_eq!(loaded.expires_at_epoch_sec, secrets.expires_at_epoch_sec);

    store.clear().unwrap();
    assert!(store.load().unwrap().is_none(), "cleared store must be empty");

    let _ = std::fs::remove_dir_all(&dir);
}
