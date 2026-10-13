use ifoxy_windows::vpn::killswitch::{KillSwitchGuard, KillSwitchPolicy, MockFirewallBackend};
use ifoxy_windows::vpn::packet::{build_tcp_syn_ack_packet, TcpHeader};
use ifoxy_windows::vpn::wintun_adapter::{
    resolve_vpn_ip_avoiding_conflict, DEFAULT_WINTUN_IP, FALLBACK_WINTUN_IP, IFOXY_ADAPTER_GUID,
    VPN_ADAPTER_MTU, VPN_TCP_MSS,
};
use std::net::Ipv4Addr;
use std::sync::Arc;

#[test]
fn test_wintun_address_conflict_detection() {
    // No conflict: standard home LAN
    let home_gw = Some(Ipv4Addr::new(192, 168, 1, 1));
    let resolved = resolve_vpn_ip_avoiding_conflict(DEFAULT_WINTUN_IP, home_gw);
    assert_eq!(resolved, DEFAULT_WINTUN_IP);

    // No conflict: public / non-overlapping gateway
    let public_gw = Some(Ipv4Addr::new(10, 0, 0, 1));
    let resolved2 = resolve_vpn_ip_avoiding_conflict(DEFAULT_WINTUN_IP, public_gw);
    assert_eq!(resolved2, DEFAULT_WINTUN_IP);

    // Conflict: gateway is on 10.254.1.x subnet! (M5)
    let conflicting_gw = Some(Ipv4Addr::new(10, 254, 1, 254));
    let resolved_fallback = resolve_vpn_ip_avoiding_conflict(DEFAULT_WINTUN_IP, conflicting_gw);
    assert_eq!(
        resolved_fallback, FALLBACK_WINTUN_IP,
        "Subnet collision must choose alternative non-conflicting IP"
    );
}

#[test]
fn test_wintun_guid_and_mtu_mss_constants() {
    assert_eq!(VPN_ADAPTER_MTU, 1420);
    assert_eq!(VPN_TCP_MSS, 1380);
    assert_ne!(IFOXY_ADAPTER_GUID, 0);
}

#[test]
fn test_syn_ack_mss_option_clamping() {
    let packet = build_tcp_syn_ack_packet(
        Ipv4Addr::new(10, 254, 1, 1),
        Ipv4Addr::new(10, 254, 1, 100),
        80,
        12345,
        1000,
        2000,
        65535,
        VPN_TCP_MSS,
    );

    // Total length: 20 IP + 24 TCP = 44 bytes
    assert_eq!(packet.len(), 44);

    let tcp_slice = &packet[20..];
    let (tcp_hdr, _) = TcpHeader::parse(tcp_slice).expect("Parse TCP header");
    assert_eq!(tcp_hdr.data_offset, 24);

    // Option Kind 2 (MSS)
    assert_eq!(packet[40], 0x02, "TCP Option Kind must be 2 (MSS)");
    assert_eq!(packet[41], 0x04, "TCP Option Length must be 4");
    let parsed_mss = u16::from_be_bytes([packet[42], packet[43]]);
    assert_eq!(parsed_mss, 1380, "MSS value must be clamped to 1380 (M5)");
}

#[test]
fn test_killswitch_and_ipv6_leak_prevention() {
    let mock_firewall = Arc::new(MockFirewallBackend::new());
    let mut guard = KillSwitchGuard::new(mock_firewall.clone());

    let policy = KillSwitchPolicy {
        kill_switch_enabled: true,
        block_ipv6_leaks: true,
        edge_ip: Some(Ipv4Addr::new(151, 101, 1, 140)),
        wintun_if_index: Some(42),
        wintun_local_ip: Some(Ipv4Addr::new(10, 254, 1, 1)),
    };

    guard.apply(&policy).expect("Apply killswitch");
    assert!(guard.is_active());

    {
        let rules = mock_firewall.installed_rules.lock().unwrap();
        assert!(rules.contains(&"iFoxy_Block_IPv6_Leak".to_string()));
        assert!(rules.contains(&"iFoxy_KillSwitch_Block_All".to_string()));
        assert!(rules.contains(&"iFoxy_KillSwitch_Allow_Edge".to_string()));
        assert!(rules.contains(&"iFoxy_KillSwitch_Allow_Loopback".to_string()));
    }

    // Clean guard
    guard.clean();
    assert!(!guard.is_active());
    assert_eq!(mock_firewall.installed_rules.lock().unwrap().len(), 0);
}
