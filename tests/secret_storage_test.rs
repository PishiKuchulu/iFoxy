use ifoxy_windows::auth::secret_storage::{SecretStore, StoredSecrets};

#[test]
fn test_secret_storage_dpapi_roundtrip_and_no_plaintext() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifoxy_test_secrets_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let secret_file = temp_dir.join("session.enc");

    let store = SecretStore::with_path(secret_file.clone());

    let test_token = "SUPER_SECRET_OAUTH_ACCESS_TOKEN_123456789";
    let test_refresh = "SUPER_SECRET_REFRESH_TOKEN_987654321";

    let secrets = StoredSecrets {
        email: "user@example.com".to_string(),
        uid: "fxa_uid_abcdef".to_string(),
        access_token: test_token.to_string(),
        refresh_token: Some(test_refresh.to_string()),
        expires_at_epoch_sec: Some(1893456000),
    };

    // Save secrets
    store.save(&secrets).expect("Save secrets should succeed");

    // Verify file exists on disk
    assert!(secret_file.exists());
    let raw_bytes = std::fs::read(&secret_file).expect("Must read secret file");

    // Test C7 requirement: "the stored file contains no plaintext token (search the bytes)"
    let raw_str = String::from_utf8_lossy(&raw_bytes);
    assert!(
        !raw_str.contains(test_token),
        "Secret file MUST NOT contain plaintext access token!"
    );
    assert!(
        !raw_str.contains(test_refresh),
        "Secret file MUST NOT contain plaintext refresh token!"
    );

    // Verify roundtrip decryption
    let loaded = store
        .load()
        .expect("Load should succeed")
        .expect("Must have secrets");
    assert_eq!(loaded.email, "user@example.com");
    assert_eq!(loaded.uid, "fxa_uid_abcdef");
    assert_eq!(loaded.access_token, test_token);
    assert_eq!(loaded.refresh_token, Some(test_refresh.to_string()));
    assert_eq!(loaded.expires_at_epoch_sec, Some(1893456000));

    // Test clean removal / zeroize
    store.clear().expect("Clear must succeed");
    assert!(
        !secret_file.exists(),
        "Secret file must be deleted on clear"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}
