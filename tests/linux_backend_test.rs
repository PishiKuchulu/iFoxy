#![cfg(target_os = "linux")]
//! End-to-end plumbing test for the Linux Full-mode backend: real TUN
//! device, real routes through RouteManager, real iptables kill switch.
//! Ignored by default — run explicitly as root:
//!   sudo cargo test --test linux_backend_test -- --ignored

use ifoxy_windows::vpn::killswitch::{FirewallBackend, KillSwitchPolicy, LinuxFirewallBackend};
use ifoxy_windows::vpn::linux_tun::LinuxTunDevice;
use ifoxy_windows::vpn::packet_pump::TunDeviceOps;
use ifoxy_windows::vpn::routing::{detect_default_gateway_and_interface, RouteManager};
use std::net::Ipv4Addr;
use std::process::Command;

fn sh(program: &str, args: &[&str]) -> String {
    let out = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {}", program, e));
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
#[ignore = "requires root: creates a real TUN device, routes and iptables chains"]
fn linux_full_mode_plumbing_end_to_end() {
    // 1. Default gateway + interface detection from /proc/net/route.
    let (gw, phys_if) = detect_default_gateway_and_interface().expect("gateway detection");
    assert_ne!(gw, Ipv4Addr::UNSPECIFIED);
    assert!(phys_if > 0, "physical ifindex must be resolved");

    // 2. TUN device comes up with the VPN address and MTU.
    let device = LinuxTunDevice::create_or_open(Ipv4Addr::new(10, 254, 1, 1)).expect("TUN create");
    assert_eq!(device.ip(), Ipv4Addr::new(10, 254, 1, 1));
    assert!(device.adapter_index() > 0);
    let link = sh("ip", &["link", "show", "ifoxy0"]);
    assert!(link.contains("mtu 1420"), "unexpected link state: {}", link);
    assert!(link.contains("UP"), "link not up: {}", link);
    let addr = sh("ip", &["addr", "show", "ifoxy0"]);
    assert!(addr.contains("10.254.1.1/24"), "unexpected addr: {}", addr);

    // 3. RouteManager installs the edge bypass + split default routes.
    let edge = Ipv4Addr::new(151, 101, 1, 140);
    let guard = RouteManager::install_vpn_routes(
        edge,
        gw,
        phys_if,
        device.ip(),
        device.adapter_index(),
    )
    .expect("route install");
    let routes = sh("ip", &["route", "show"]);
    assert!(routes.contains("0.0.0.0/1"), "missing split route 1: {}", routes);
    assert!(
        routes.contains("128.0.0.0/1"),
        "missing split route 2: {}",
        routes
    );
    assert!(
        routes.contains("151.101.1.140"),
        "missing edge bypass: {}",
        routes
    );

    // 4. Kill switch installs the WFP-mirroring iptables rules.
    let backend = LinuxFirewallBackend::new();
    let policy = KillSwitchPolicy {
        kill_switch_enabled: true,
        block_ipv6_leaks: true,
        edge_ip: Some(edge),
        wintun_if_index: Some(device.adapter_index()),
        wintun_local_ip: Some(device.ip()),
    };
    let ids = backend.install_kill_switch(&policy).expect("kill switch install");
    assert!(!ids.is_empty());
    let rules = sh("iptables", &["-S", "IFOXY_KS"]);
    assert!(rules.contains("-j DROP"), "no final DROP: {}", rules);
    assert!(
        rules.contains("151.101.1.140"),
        "no edge permit: {}",
        rules
    );
    let rules6 = sh("ip6tables", &["-S", "IFOXY_KS6"]);
    assert!(rules6.contains("-j DROP"), "no v6 DROP: {}", rules6);

    // 5. Teardown: kill switch chains gone, routes gone with the guard.
    backend.remove_kill_switch(&ids).expect("kill switch remove");
    let after = sh("iptables", &["-S", "IFOXY_KS"]);
    assert!(
        after.contains("No chain")
            || after.contains("does not exist")
            || !after.contains("IFOXY_KS"),
        "chain survived remove: {}",
        after
    );
    drop(guard);
    let routes = sh("ip", &["route", "show"]);
    assert!(
        !routes.contains("0.0.0.0/1"),
        "split route survived guard drop: {}",
        routes
    );
    drop(device);
    let link = sh("ip", &["link", "show", "ifoxy0"]);
    assert!(
        link.contains("does not exist"),
        "TUN device survived drop: {}",
        link
    );
}
