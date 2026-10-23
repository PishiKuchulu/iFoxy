use ifoxy_windows::vpn::network_backend::NetworkBackend;
use ifoxy_windows::vpn::system_proxy::ProxySettingsBackup;
use ifoxy_windows::vpn::routing::{
    is_private_or_loopback, split_tunnel_routes, RouteDefinition, RouteError, RouteManager,
};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

struct FailingMockBackend {
    fail_at_step: usize,
    call_count: Mutex<usize>,
    deleted_routes: Mutex<Vec<(RouteDefinition, u32)>>,
}

impl FailingMockBackend {
    fn new(fail_at_step: usize) -> Self {
        Self {
            fail_at_step,
            call_count: Mutex::new(0),
            deleted_routes: Mutex::new(Vec::new()),
        }
    }

    fn deleted_count(&self) -> usize {
        self.deleted_routes.lock().unwrap().len()
    }
}

impl NetworkBackend for FailingMockBackend {
    fn detect_default_gateway(&self) -> Result<Ipv4Addr, RouteError> {
        Ok(Ipv4Addr::new(192, 168, 1, 1))
    }

    fn add_route(&self, _route: &RouteDefinition, _if_index: u32) -> Result<(), RouteError> {
        let mut count = self.call_count.lock().unwrap();
        let step = *count;
        *count += 1;
        if step == self.fail_at_step {
            Err(RouteError::CommandFailed(format!(
                "Injected failure at step {}",
                step
            )))
        } else {
            Ok(())
        }
    }

    fn delete_route(&self, route: &RouteDefinition, if_index: u32) -> Result<(), RouteError> {
        self.deleted_routes
            .lock()
            .unwrap()
            .push((route.clone(), if_index));
        Ok(())
    }

    fn set_system_proxy(&self, _port: u16) -> Result<(), String> {
        Ok(())
    }

    fn restore_system_proxy(&self, _backup: Option<&ProxySettingsBackup>) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn test_private_ip_detection() {
    assert!(is_private_or_loopback(Ipv4Addr::new(127, 0, 0, 1)));
    assert!(is_private_or_loopback(Ipv4Addr::new(10, 0, 0, 1)));
    assert!(is_private_or_loopback(Ipv4Addr::new(172, 16, 0, 1)));
    assert!(is_private_or_loopback(Ipv4Addr::new(172, 31, 255, 254)));
    assert!(is_private_or_loopback(Ipv4Addr::new(192, 168, 1, 1)));
    assert!(is_private_or_loopback(Ipv4Addr::new(169, 254, 1, 1))); // Link local

    assert!(!is_private_or_loopback(Ipv4Addr::new(1, 1, 1, 1)));
    assert!(!is_private_or_loopback(Ipv4Addr::new(8, 8, 8, 8)));
    assert!(!is_private_or_loopback(Ipv4Addr::new(151, 101, 1, 1)));
}

#[test]
fn test_split_tunnel_routes() {
    let gateway = Ipv4Addr::new(10, 254, 1, 1);
    let routes = split_tunnel_routes(gateway);
    assert_eq!(routes.len(), 2);

    assert_eq!(routes[0].destination, Ipv4Addr::new(0, 0, 0, 0));
    assert_eq!(routes[0].prefix_len, 1);
    assert_eq!(routes[0].gateway, gateway);

    assert_eq!(routes[1].destination, Ipv4Addr::new(128, 0, 0, 0));
    assert_eq!(routes[1].prefix_len, 1);
    assert_eq!(routes[1].gateway, gateway);
}

#[test]
fn test_route_add_fails_at_step_0_edge_bypass_rolls_back_and_returns_error() {
    let backend = Arc::new(FailingMockBackend::new(0)); // Fail at edge bypass
    let res = RouteManager::install_vpn_routes_with_backend(
        Ipv4Addr::new(1, 2, 3, 4),
        Ipv4Addr::new(192, 168, 1, 1),
        2, // physical_if_idx
        Ipv4Addr::new(10, 64, 0, 2),
        15, // wintun_if_idx
        backend.clone(),
        false,
    );

    assert!(
        res.is_err(),
        "Must return Err when edge bypass route addition fails"
    );
}

#[test]
fn test_route_add_fails_at_step_1_first_split_route_rolls_back_edge_bypass() {
    let backend = Arc::new(FailingMockBackend::new(1)); // Fail at first split route
    let res = RouteManager::install_vpn_routes_with_backend(
        Ipv4Addr::new(1, 2, 3, 4),
        Ipv4Addr::new(192, 168, 1, 1),
        2, // physical_if_idx
        Ipv4Addr::new(10, 64, 0, 2),
        15, // wintun_if_idx
        backend.clone(),
        false,
    );

    assert!(
        res.is_err(),
        "Must return Err when first split route addition fails"
    );
    assert_eq!(
        backend.deleted_count(),
        1,
        "Must roll back edge bypass route when split route fails"
    );
    let deleted = backend.deleted_routes.lock().unwrap();
    assert_eq!(
        deleted[0].1, 2,
        "Edge bypass route must be rolled back using physical_if_idx"
    );
    assert_eq!(deleted[0].0.destination, Ipv4Addr::new(1, 2, 3, 4));
}

#[test]
fn test_route_add_fails_at_step_2_second_split_route_rolls_back_all() {
    let backend = Arc::new(FailingMockBackend::new(2)); // Fail at second split route
    let res = RouteManager::install_vpn_routes_with_backend(
        Ipv4Addr::new(1, 2, 3, 4),
        Ipv4Addr::new(192, 168, 1, 1),
        2, // physical_if_idx
        Ipv4Addr::new(10, 64, 0, 2),
        15, // wintun_if_idx
        backend.clone(),
        false,
    );

    assert!(
        res.is_err(),
        "Must return Err when second split route addition fails"
    );
    assert_eq!(
        backend.deleted_count(),
        2,
        "Must roll back both edge bypass route and first split route"
    );
    let deleted = backend.deleted_routes.lock().unwrap();
    assert_eq!(
        deleted[0].1, 15,
        "First split route must be deleted using wintun_if_idx"
    );
    assert_eq!(
        deleted[1].1, 2,
        "Edge bypass route must be deleted using physical_if_idx"
    );
}

#[test]
fn test_reapply_edge_bypass_on_network_change() {
    let mock_gw1 = Ipv4Addr::new(192, 168, 1, 1);
    let mock_gw2 = Ipv4Addr::new(10, 0, 0, 1);
    let backend = Arc::new(FailingMockBackend::new(999)); // No failure
    let edge_ip = Ipv4Addr::new(1, 2, 3, 4);
    let wintun_ip = Ipv4Addr::new(10, 64, 0, 2);
    let mut guard = RouteManager::install_vpn_routes_with_backend(
        edge_ip,
        mock_gw1,
        2,
        wintun_ip,
        15,
        backend.clone(),
        false,
    )
    .expect("install routes");

    // Network changed: new gateway and new physical if_index 8
    guard
        .reapply_edge_bypass(mock_gw2, 8)
        .expect("reapply bypass");
    assert_eq!(guard.physical_if_idx(), 8);

    // Old edge route was deleted from interface 2
    let deleted = backend.deleted_routes.lock().unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].1, 2);
}
