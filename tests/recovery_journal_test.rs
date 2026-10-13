use ifoxy_windows::vpn::network_backend::{MockNetworkBackend, NetworkBackend};
use ifoxy_windows::vpn::recovery_journal::RecoveryJournal;
use ifoxy_windows::vpn::registry::ProxySettingsBackup;
use ifoxy_windows::vpn::routing::{RouteDefinition, RouteManager};
use std::net::Ipv4Addr;
use std::sync::Arc;

#[test]
fn test_recovery_journal_records_and_replays_dirty_state() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifoxy_test_journal_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let journal_path = temp_dir.join("recovery_journal.json");

    let mock_gw = Ipv4Addr::new(192, 168, 1, 1);
    let mock_backend = Arc::new(MockNetworkBackend::new(mock_gw));

    // 1. Create and populate journal as if VPN was activated
    let mut journal = RecoveryJournal::new(journal_path.clone());
    journal.record_edge_bypass(Ipv4Addr::new(151, 101, 1, 140), mock_gw, 5);
    journal.record_route(
        RouteDefinition {
            destination: Ipv4Addr::new(0, 0, 0, 0),
            prefix_len: 1,
            gateway: Ipv4Addr::new(10, 254, 1, 1),
            metric: 1,
        },
        42,
    );
    journal.record_route(
        RouteDefinition {
            destination: Ipv4Addr::new(128, 0, 0, 0),
            prefix_len: 1,
            gateway: Ipv4Addr::new(10, 254, 1, 1),
            metric: 1,
        },
        42,
    );
    journal.record_proxy_backup(ProxySettingsBackup {
        proxy_enable: Some(0),
        proxy_server: None,
        proxy_override: None,
    });

    journal.flush_to_disk().expect("Flush journal to disk");
    assert!(journal_path.exists(), "Journal file must exist on disk");

    // 2. Simulate process crash by dropping journal without calling mark_clean()
    drop(journal);
    assert!(
        journal_path.exists(),
        "Journal file remains after simulated crash"
    );

    // 3. New process startup runs crash recovery (H5)
    let recovered = RecoveryJournal::recover_if_dirty(&journal_path, mock_backend.as_ref())
        .expect("Crash recovery execution");
    assert!(recovered, "Must report dirty journal recovered");

    // 4. Verify mock backend received cleanup calls
    // Deleted routes: 2 split routes + 1 edge bypass route = 3 deleted
    assert_eq!(mock_backend.deleted_count(), 3);
    assert_eq!(*mock_backend.proxy_enabled_port.lock().unwrap(), None);

    // 5. Journal file must be removed after successful recovery
    assert!(
        !journal_path.exists(),
        "Journal file must be deleted after recovery"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_route_manager_with_mock_backend_and_clean_exit() {
    let mock_gw = Ipv4Addr::new(192, 168, 1, 1);
    let mock_backend = Arc::new(MockNetworkBackend::new(mock_gw));

    let edge_ip = Ipv4Addr::new(151, 101, 65, 140);
    let wintun_ip = Ipv4Addr::new(10, 254, 1, 1);
    let wintun_if_idx = 10;

    let physical_if_idx = 5;
    let mut guard = RouteManager::install_vpn_routes_with_backend(
        edge_ip,
        mock_gw,
        physical_if_idx,
        wintun_ip,
        wintun_if_idx,
        mock_backend.clone(),
        false, // Skip disk journal in this test
    )
    .expect("Install routes");

    assert_eq!(guard.installed_routes().len(), 2);
    assert_eq!(guard.edge_bypass_ip(), Some(edge_ip));
    assert_eq!(mock_backend.installed_count(), 3); // 1 edge route + 2 split routes

    // Clean routes
    guard.clean();
    assert_eq!(mock_backend.installed_count(), 0);
    assert_eq!(mock_backend.deleted_count(), 3);
}

#[test]
fn test_recovery_journal_fault_injection_after_each_step() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifoxy_fault_journal_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let mock_gw = Ipv4Addr::new(192, 168, 1, 1);
    let edge_ip = Ipv4Addr::new(151, 101, 65, 140);
    let wintun_ip = Ipv4Addr::new(10, 254, 1, 1);

    // Case 1: Crash immediately after edge bypass route is recorded and installed
    {
        let journal_path = temp_dir.join("journal_step1.json");
        let mock_backend = Arc::new(MockNetworkBackend::new(mock_gw));

        let mut journal = RecoveryJournal::new(journal_path.clone());
        journal.record_edge_bypass(edge_ip, mock_gw, 5);
        journal.flush_to_disk().expect("flush edge bypass");

        let edge_route = RouteDefinition {
            destination: edge_ip,
            prefix_len: 32,
            gateway: mock_gw,
            metric: 1,
        };
        mock_backend
            .add_route(&edge_route, 5)
            .expect("add edge route");
        assert_eq!(mock_backend.installed_count(), 1);

        // Crash occurs (journal dropped without mark_clean)
        drop(journal);

        // Next startup recovers
        let recovered = RecoveryJournal::recover_if_dirty(&journal_path, mock_backend.as_ref())
            .expect("recover step 1");
        assert!(recovered);
        assert_eq!(mock_backend.installed_count(), 0);
        assert_eq!(mock_backend.deleted_count(), 1);
        assert!(!journal_path.exists());
    }

    // Case 2: Crash after first split route (0.0.0.0/1) is recorded and installed
    {
        let journal_path = temp_dir.join("journal_step2.json");
        let mock_backend = Arc::new(MockNetworkBackend::new(mock_gw));

        let mut journal = RecoveryJournal::new(journal_path.clone());
        journal.record_edge_bypass(edge_ip, mock_gw, 5);
        let r1 = RouteDefinition {
            destination: Ipv4Addr::new(0, 0, 0, 0),
            prefix_len: 1,
            gateway: wintun_ip,
            metric: 1,
        };
        journal.record_route(r1.clone(), 10);
        journal.flush_to_disk().expect("flush step 2");

        mock_backend.add_route(&r1, 10).expect("add r1");
        assert_eq!(mock_backend.installed_count(), 1);

        // Crash occurs
        drop(journal);

        // Next startup recovers
        let recovered = RecoveryJournal::recover_if_dirty(&journal_path, mock_backend.as_ref())
            .expect("recover step 2");
        assert!(recovered);
        assert_eq!(mock_backend.installed_count(), 0);
        assert_eq!(mock_backend.deleted_count(), 2); // r1 + edge bypass
        assert!(!journal_path.exists());
    }

    // Case 3: Crash in ProxyOnly mode after proxy backup is written
    {
        let journal_path = temp_dir.join("journal_proxy.json");
        let mock_backend = Arc::new(MockNetworkBackend::new(mock_gw));

        // Initial system proxy was pointing to corporate proxy 192.168.1.254:8080
        let original_backup = ProxySettingsBackup {
            proxy_enable: Some(1),
            proxy_server: Some("192.168.1.254:8080".to_string()),
            proxy_override: Some("<local>".to_string()),
        };

        // Write journal before mutating proxy
        let mut journal = RecoveryJournal::new(journal_path.clone());
        journal.record_proxy_backup(original_backup.clone());
        journal.flush_to_disk().expect("flush proxy backup");

        // Mutate proxy to iFoxy local proxy 10800
        mock_backend.set_system_proxy(10800).unwrap();
        assert_eq!(
            *mock_backend.proxy_enabled_port.lock().unwrap(),
            Some(10800)
        );

        // Crash occurs in ProxyOnly mode
        drop(journal);

        // Next startup recovers
        let recovered = RecoveryJournal::recover_if_dirty(&journal_path, mock_backend.as_ref())
            .expect("recover proxy mode");
        assert!(recovered);

        // Proxy must be restored to clean/original state
        assert_eq!(*mock_backend.proxy_enabled_port.lock().unwrap(), None);
        assert!(!journal_path.exists());
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_recovery_journal_clean_shutdown_removes_file() {
    let temp_dir =
        std::env::temp_dir().join(format!("ifoxy_clean_journal_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let journal_path = temp_dir.join("recovery_journal.json");

    let journal = RecoveryJournal::new(journal_path.clone());
    journal.flush_to_disk().expect("Flush journal");
    assert!(journal_path.exists());

    journal.mark_clean();
    assert!(
        !journal_path.exists(),
        "mark_clean must remove journal file"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}
