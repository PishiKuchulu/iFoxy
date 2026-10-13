use ifoxy_windows::logging::{redact_sensitive_text, RollingFileWriter};
use std::fs;

#[test]
fn test_sensitive_data_redaction() {
    // 1. Bearer token
    let log1 = "Authorization: Bearer secret_oauth_token_12345 in header";
    let redacted1 = redact_sensitive_text(log1);
    assert_eq!(redacted1, "Authorization: Bearer [REDACTED] in header");

    // 2. Hawk credentials
    let log2 = "Sent Hawk id=\"my_secret_token_id\", ts=\"1700000000\", nonce=\"xyz\", mac=\"secret_mac_hash\"";
    let redacted2 = redact_sensitive_text(log2);
    assert!(redacted2.contains("Hawk id=\"[REDACTED]\""));
    assert!(redacted2.contains("mac=\"[REDACTED]\""));
    assert!(!redacted2.contains("my_secret_token_id"));
    assert!(!redacted2.contains("secret_mac_hash"));

    // 3. JSON password and tokens
    let log3 = r#"Payload {"email": "user@test.com", "password": "SuperSecretPassword123!", "token": "priv_pass_token_abc"}"#;
    let redacted3 = redact_sensitive_text(log3);
    assert!(redacted3.contains(r#""password": "[REDACTED]""#));
    assert!(redacted3.contains(r#""token": "[REDACTED]""#));
    assert!(!redacted3.contains("SuperSecretPassword123!"));
    assert!(!redacted3.contains("priv_pass_token_abc"));

    // 4. X-iFoxy-Token header
    let log4 = "Incoming HTTP request x-ifoxy-token: secret_csrf_token_xyz from 127.0.0.1";
    let redacted4 = redact_sensitive_text(log4);
    assert_eq!(
        redacted4,
        "Incoming HTTP request x-ifoxy-token: [REDACTED] from 127.0.0.1"
    );
}

#[test]
fn test_rolling_file_rotation() {
    let temp_dir = std::env::temp_dir().join(format!("ifoxy_log_test_{}", rand::random::<u64>()));
    let _ = fs::create_dir_all(&temp_dir);
    let log_file = temp_dir.join("ifoxy.log");

    // Max 100 bytes per log file, max 3 files
    let mut writer = RollingFileWriter::new(log_file.clone(), 100, 3).expect("create logger");

    // Write lines exceeding 100 bytes
    for i in 1..=5 {
        writer
            .write_log_line(&format!("Log event message line number {}", i))
            .expect("write line");
    }

    // Verify base log exists
    assert!(log_file.exists());

    // Verify rotated log exists
    let backup_1 = temp_dir.join("ifoxy.log.1");
    assert!(
        backup_1.exists(),
        "Rotated log file ifoxy.log.1 must exist"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}
