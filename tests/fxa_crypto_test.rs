use base64::Engine;
use ifoxy_windows::crypto::fxa_kdf::{
    derive_auth_pw, derive_hawk_credentials, derive_quick_stretch,
};
use ifoxy_windows::crypto::hawk::{
    generate_hawk_header, generate_hawk_header_with_ts, get_clock_skew_offset,
    reset_clock_skew_offset, set_clock_skew_offset, update_clock_skew_from_server,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[test]
fn test_fxa_auth_pw_derivation() {
    let auth_pw = derive_auth_pw("test@example.com", "Password123!").expect("derivation failed");
    assert_eq!(auth_pw.len(), 64); // 32 bytes hex encoded

    // Deterministic check: repeating derivation yields identical result
    let auth_pw2 = derive_auth_pw("test@example.com", "Password123!").expect("derivation failed");
    assert_eq!(auth_pw, auth_pw2);

    // Different email yields different authPW
    let auth_pw3 = derive_auth_pw("other@example.com", "Password123!").expect("derivation failed");
    assert_ne!(auth_pw, auth_pw3);
}

#[test]
fn test_fxa_quick_stretch_and_hawk_credentials_vectors() {
    let qs = derive_quick_stretch("user@example.com", "SecretPass!").expect("quickStretch");
    assert_eq!(qs.len(), 32);

    // Test session token expansion to hawk credentials
    let dummy_session_token_hex =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let (token_id, hmac_key) =
        derive_hawk_credentials(dummy_session_token_hex).expect("derive_hawk_credentials");
    assert_eq!(token_id.len(), 64);
    assert_eq!(hmac_key.len(), 32);

    // Verification that repeated expansion is deterministic
    let (token_id_2, hmac_key_2) =
        derive_hawk_credentials(dummy_session_token_hex).expect("derive_hawk_credentials 2");
    assert_eq!(token_id, token_id_2);
    assert_eq!(hmac_key, hmac_key_2);
}

#[test]
fn test_hawk_header_deterministic_known_vector() {
    let key = [0x42u8; 32];
    let method = "GET";
    let url = "https://api.accounts.firefox.com/v1/account";
    let token_id = "tok_test_42";
    let ts = "1700000000";
    let nonce = "testnonce123";

    let header =
        generate_hawk_header_with_ts(method, url, token_id, &key, b"", Some(ts), Some(nonce))
            .expect("hawk generation failed");

    // Compute expected MAC independently
    let normalized = format!(
        "hawk.1.header\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n\n",
        ts, nonce, "GET", "/v1/account", "api.accounts.firefox.com", "443", ""
    );
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(normalized.as_bytes());
    let expected_mac =
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    let expected_header = format!(
        "Hawk id=\"{}\", ts=\"{}\", nonce=\"{}\", mac=\"{}\"",
        token_id, ts, nonce, expected_mac
    );

    assert_eq!(header, expected_header);
}

#[test]
fn test_hawk_clock_skew_compensation() {
    reset_clock_skew_offset();
    assert_eq!(get_clock_skew_offset(), 0);

    // Set clock skew offset of +3600 seconds (1 hour forward)
    set_clock_skew_offset(3600);
    assert_eq!(get_clock_skew_offset(), 3600);

    let key = [0x11u8; 32];
    let header = generate_hawk_header(
        "GET",
        "https://api.accounts.firefox.com/v1/account",
        "token_skew",
        &key,
        b"",
    )
    .expect("generate header with skew");

    // Verify timestamp in header reflects the offset
    let ts_prefix = "ts=\"";
    let ts_start = header.find(ts_prefix).unwrap() + ts_prefix.len();
    let ts_end = header[ts_start..].find('"').unwrap() + ts_start;
    let header_ts: u64 = header[ts_start..ts_end].parse().unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    assert!(((now + 3500)..=(now + 3700)).contains(&header_ts));

    // Test updating from server timestamp (M7)
    let fake_server_time = now + 7200; // 2 hours ahead
    update_clock_skew_from_server(fake_server_time);
    let offset = get_clock_skew_offset();
    assert!((7190..=7210).contains(&offset));

    reset_clock_skew_offset();
    assert_eq!(get_clock_skew_offset(), 0);
}
