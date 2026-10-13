use ifoxy_windows::security::*;
use std::fs;

#[test]
fn test_tampered_binary_is_strictly_refused() {
    let temp_dir = std::env::temp_dir().join(format!("ifoxy_sec_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    let legitimate_binary = b"MZ\x90\x00_LEGITIMATE_SIGNED_IFOXY_BINARY_CONTENT_HERE";
    let legitimate_hash = compute_sha256_hex(legitimate_binary);

    let bin_path = temp_dir.join("ifoxy_app.exe");

    // 1. Safe write and verify legitimate binary
    safe_write_and_verify(&bin_path, legitimate_binary, &legitimate_hash)
        .expect("Legitimate binary must verify and write successfully");

    // 2. Attacker tampers with the binary on disk (C3 LPE attack vector)
    let tampered_payload = b"MZ\x90\x00_MALICIOUS_TAMPERED_INJECTED_CODE_HERE_________";
    fs::write(&bin_path, tampered_payload).expect("Write tampered file");

    // 3. System verification before execution MUST refuse tampered file
    let verify_result = verify_file_hash(&bin_path, &legitimate_hash);
    assert!(
        verify_result.is_err(),
        "Verification MUST fail when file on disk has been tampered with!"
    );

    match verify_result {
        Err(SecurityError::IntegrityMismatch { expected, actual }) => {
            assert_eq!(expected, legitimate_hash);
            assert_ne!(actual, legitimate_hash);
        }
        other => panic!("Expected IntegrityMismatch, got: {:?}", other),
    }

    // 4. Also assert that writing with mismatched hash is rejected
    let bad_write = safe_write_and_verify(&bin_path, tampered_payload, &legitimate_hash);
    assert!(bad_write.is_err());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_safe_dll_search_and_single_instance() {
    // Verify SetDefaultDllDirectories call doesn't error
    enforce_safe_dll_search();

    // Verify single instance mutex
    let mutex_1 = check_single_instance("Global\\iFoxy_Test_Instance_Mutex");
    assert!(mutex_1, "First instance must succeed");
}

#[test]
fn test_tampered_wintun_dll_refused() {
    let temp_dir = std::env::temp_dir().join(format!("ifoxy_wintun_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    let wintun_path = temp_dir.join("wintun.dll");
    // Place tampered wintun.dll in directory
    let tampered_bytes = b"MZ\x90\x00_FAKE_TAMPERED_WINTUN_DLL_CONTENT_1234567890";
    fs::write(&wintun_path, tampered_bytes).expect("Write fake wintun.dll");

    // ensure_wintun_dll_at MUST refuse the tampered file
    let result = ifoxy_windows::vpn::wintun_adapter::ensure_wintun_dll_at(&temp_dir);
    assert!(
        result.is_err(),
        "Tampered wintun.dll MUST be rejected with error!"
    );

    let err_msg = format!("{:?}", result.err().unwrap());
    assert!(
        err_msg.contains("integrity verification failed"),
        "Error message should mention integrity verification failure, got: {}",
        err_msg
    );

    // Remove tampered file and call again; should extract and verify legitimate DLL
    let _ = fs::remove_file(&wintun_path);
    let extracted = ifoxy_windows::vpn::wintun_adapter::ensure_wintun_dll_at(&temp_dir);
    assert!(
        extracted.is_ok(),
        "Extracting official embedded wintun.dll should succeed: {:?}",
        extracted.err()
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wintun_authenticode_signature_verified() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifoxy_authcode_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    // 1. Extract valid embedded wintun.dll and verify Authenticode signature
    let extracted = ifoxy_windows::vpn::wintun_adapter::ensure_wintun_dll_at(&temp_dir)
        .expect("Extract embedded wintun.dll");
    let auth_res = verify_authenticode_signature(&extracted);
    assert!(
        auth_res.is_ok(),
        "Embedded wintun.dll must have a valid Authenticode signature: {:?}",
        auth_res.err()
    );

    // 2. An unsigned / tampered binary must fail WinVerifyTrust
    let unsigned_path = temp_dir.join("unsigned.dll");
    fs::write(&unsigned_path, b"MZ_UNSIGNED_DUMMY_DLL_PAYLOAD").expect("Write unsigned");
    let unsigned_res = verify_authenticode_signature(&unsigned_path);
    assert!(
        unsigned_res.is_err(),
        "Unsigned binary must fail WinVerifyTrust verification"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_tampered_webview2_loader_dll_refused() {
    let temp_dir = std::env::temp_dir().join(format!("ifoxy_wv2_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    let wv2_path = temp_dir.join("WebView2Loader.dll");
    let tampered_bytes = b"MZ\x90\x00_FAKE_TAMPERED_WEBVIEW2_LOADER_DLL_CONTENT";
    fs::write(&wv2_path, tampered_bytes).expect("Write fake WebView2Loader.dll");

    let result = verify_webview2_loader_dll_at(&temp_dir);
    assert!(
        result.is_err(),
        "Tampered WebView2Loader.dll MUST be rejected with error!"
    );

    let _ = fs::remove_file(&wv2_path);
    assert!(
        verify_webview2_loader_dll_at(&temp_dir).is_ok(),
        "Absent DLL should pass (system library used)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn install_location_policy_allows_only_admin_writable_roots() {
    use ifoxy_windows::security::{
        check_install_location, is_path_under, is_secure_install_location, SecurityError,
    };
    use std::path::{Path, PathBuf};

    let roots = vec![
        PathBuf::from(r"C:\Program Files"),
        PathBuf::from(r"C:\Program Files (x86)"),
    ];

    assert!(is_secure_install_location(
        Path::new(r"C:\Program Files\iFoxy"),
        &roots
    ));
    assert!(is_secure_install_location(
        Path::new(r"c:\program files\ifoxy\"),
        &roots
    ));
    assert!(is_secure_install_location(
        Path::new(r"\\?\C:\Program Files\iFoxy"),
        &roots
    ));

    // User-writable places and look-alike prefixes must be rejected.
    assert!(!is_secure_install_location(
        Path::new(r"C:\Users\bob\AppData\Local\iFoxy\bin"),
        &roots
    ));
    assert!(!is_secure_install_location(
        Path::new(r"C:\Program Files Evil\iFoxy"),
        &roots
    ));
    assert!(!is_secure_install_location(
        Path::new(r"D:\Program Files\iFoxy"),
        &roots
    ));
    assert!(!is_path_under(Path::new(r"C:\x"), Path::new("")));

    // The portable opt-in bypasses the check; without it a user folder fails.
    assert!(check_install_location(Path::new(r"C:\Users\bob\Downloads"), true).is_ok());
    match check_install_location(Path::new(r"C:\Users\bob\Downloads"), false) {
        Err(SecurityError::InsecureLocation(p)) => assert!(p.contains("Downloads")),
        other => panic!("expected InsecureLocation, got {:?}", other),
    }
}
