//! Regression tests for the second external-review wave (2026-10-25).
//!
//! Each test pins one fix so a later refactor cannot silently re-open
//! the hole the reviewer found.

use ifoxy_windows::vpn::network_backend::MockNetworkBackend;
use ifoxy_windows::vpn::recovery_journal::RecoveryJournal;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// P2 (recovery fail-open): a journal file that exists but cannot be
/// parsed must surface as an Err from `recover_if_dirty` — never as a
/// silent Ok. main.rs turns that Err into a fatal startup refusal
/// instead of logging it and continuing into a connectable UI.
#[test]
fn test_corrupt_recovery_journal_is_an_error_not_a_silent_ok() {
    let temp_dir = std::env::temp_dir().join(format!(
        "ifoxy_test_corrupt_journal_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let journal_path = temp_dir.join("recovery_journal.json");
    // Torn garbage: not JSON at all, so no route/proxy state can be known.
    std::fs::write(&journal_path, b"{ this is not a journal").unwrap();

    let mock_backend = Arc::new(MockNetworkBackend::new(Ipv4Addr::new(192, 168, 1, 1)));
    let result = RecoveryJournal::recover_if_dirty(&journal_path, mock_backend.as_ref());
    assert!(
        result.is_err(),
        "corrupt journal must be an error (fail-closed startup depends on it), got {:?}",
        result
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// A missing journal is still the normal clean-startup path: Ok(false),
/// no error, nothing to replay.
#[test]
fn test_missing_recovery_journal_is_clean_startup() {
    let temp_dir = std::env::temp_dir().join(format!(
        "ifoxy_test_no_journal_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let journal_path = temp_dir.join("recovery_journal.json");

    let mock_backend = Arc::new(MockNetworkBackend::new(Ipv4Addr::new(192, 168, 1, 1)));
    let result = RecoveryJournal::recover_if_dirty(&journal_path, mock_backend.as_ref());
    assert!(!result.unwrap());

    let _ = std::fs::remove_dir_all(&temp_dir);
}
