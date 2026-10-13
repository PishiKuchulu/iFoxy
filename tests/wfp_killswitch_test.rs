use ifoxy_windows::vpn::killswitch::{
    KillSwitchGuard, KillSwitchPolicy, MockFirewallBackend, WfpRuleType,
};
use ifoxy_windows::vpn::recovery_journal::RecoveryJournal;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[test]
fn test_wfp_permit_rules_outrank_block_rules() {
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

    let rules = mock_firewall.get_installed_rule_definitions();

    // 1. Must have permit rules for Edge IP, Loopback, DHCP, and Tunnel interface
    let edge_rule = rules
        .iter()
        .find(|r| r.rule_type == WfpRuleType::PermitEdge)
        .expect("Must have PermitEdge rule");
    let loopback_rule = rules
        .iter()
        .find(|r| r.rule_type == WfpRuleType::PermitLoopback)
        .expect("Must have PermitLoopback rule");
    let dhcp_rule = rules
        .iter()
        .find(|r| r.rule_type == WfpRuleType::PermitDhcp)
        .expect("Must have PermitDhcp rule");
    let tunnel_rule = rules
        .iter()
        .find(|r| r.rule_type == WfpRuleType::PermitTunnel)
        .expect("Must have PermitTunnel rule");

    // 2. Must have block rules for Outbound IPv4 and IPv6
    let block_v4_rule = rules
        .iter()
        .find(|r| r.rule_type == WfpRuleType::BlockOutboundV4)
        .expect("Must have BlockOutboundV4 rule");
    let block_v6_rule = rules
        .iter()
        .find(|r| r.rule_type == WfpRuleType::BlockOutboundV6)
        .expect("Must have BlockOutboundV6 rule");

    // 3. Strict requirement (R-8): Permit rules MUST outrank block rules in weight
    assert!(
        edge_rule.weight > block_v4_rule.weight,
        "PermitEdge weight ({}) must be higher than BlockOutboundV4 ({})",
        edge_rule.weight,
        block_v4_rule.weight
    );
    assert!(
        loopback_rule.weight > block_v4_rule.weight,
        "PermitLoopback weight ({}) must be higher than BlockOutboundV4 ({})",
        loopback_rule.weight,
        block_v4_rule.weight
    );
    assert!(
        dhcp_rule.weight > block_v4_rule.weight,
        "PermitDhcp weight ({}) must be higher than BlockOutboundV4 ({})",
        dhcp_rule.weight,
        block_v4_rule.weight
    );
    assert!(
        tunnel_rule.weight > block_v4_rule.weight,
        "PermitTunnel weight ({}) must be higher than BlockOutboundV4 ({})",
        tunnel_rule.weight,
        block_v4_rule.weight
    );
    assert!(
        loopback_rule.weight > block_v6_rule.weight,
        "PermitLoopback weight ({}) must be higher than BlockOutboundV6 ({})",
        loopback_rule.weight,
        block_v6_rule.weight
    );
}

#[test]
fn test_wfp_killswitch_fault_injection_rolls_back_partial_rules() {
    let mock_firewall = Arc::new(MockFirewallBackend::new_with_failure_at_step(3));
    let mut guard = KillSwitchGuard::new(mock_firewall.clone());

    let policy = KillSwitchPolicy {
        kill_switch_enabled: true,
        block_ipv6_leaks: true,
        edge_ip: Some(Ipv4Addr::new(151, 101, 1, 140)),
        wintun_if_index: Some(42),
        wintun_local_ip: Some(Ipv4Addr::new(10, 254, 1, 1)),
    };

    let res = guard.apply(&policy);
    assert!(
        res.is_err(),
        "Must return error when rule installation fails"
    );
    assert_eq!(
        mock_firewall.installed_filter_count(),
        0,
        "All partially installed rules must be rolled back on error"
    );
}

#[test]
fn test_wfp_killswitch_records_filter_ids_in_recovery_journal() {
    let temp_dir = std::env::temp_dir().join(format!("ifoxy_wfp_journal_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let journal_path = temp_dir.join("recovery_journal.json");

    let mock_firewall = Arc::new(MockFirewallBackend::new());
    let journal = RecoveryJournal::new(journal_path.clone());
    let mut guard = KillSwitchGuard::new_with_journal(mock_firewall.clone(), Some(journal));

    let policy = KillSwitchPolicy {
        kill_switch_enabled: true,
        block_ipv6_leaks: true,
        edge_ip: Some(Ipv4Addr::new(151, 101, 1, 140)),
        wintun_if_index: Some(42),
        wintun_local_ip: Some(Ipv4Addr::new(10, 254, 1, 1)),
    };

    guard.apply(&policy).expect("Apply killswitch");
    assert!(guard.is_active());
    assert!(mock_firewall.installed_filter_count() > 0);

    // Verify recovery journal was flushed to disk with filter IDs
    assert!(journal_path.exists());
    let data = std::fs::read_to_string(&journal_path).expect("read journal");
    assert!(data.contains("wfp_filters"));

    guard.clean();
    assert!(!guard.is_active());
    assert_eq!(mock_firewall.installed_filter_count(), 0);
    assert!(
        !journal_path.exists(),
        "Journal must be removed after clean shutdown"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[cfg(windows)]
#[test]
#[ignore = "requires admin: writes real WFP filters"]

fn test_real_windows_wfp_filter_lifecycle_and_readback() {
    use ifoxy_windows::vpn::killswitch::{FirewallBackend, WindowsFirewallBackend};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    let backend = WindowsFirewallBackend::new();
    let policy = KillSwitchPolicy {
        kill_switch_enabled: true,
        block_ipv6_leaks: true,
        edge_ip: Some(Ipv4Addr::new(151, 101, 1, 140)),
        wintun_if_index: Some(42),
        wintun_local_ip: Some(Ipv4Addr::new(10, 254, 1, 1)),
    };

    // 1. Install killswitch into real WFP engine
    let filter_ids = backend
        .install_kill_switch(&policy)
        .expect("Install real WFP filters");
    assert_eq!(
        filter_ids.len(),
        7,
        "Expected 7 filters (4 v4 permit, 1 v4 block, 1 v6 permit, 1 v6 block)"
    );

    // 2. Open an independent, second WFP session to read back and verify the filters
    let mut reader_handle: HANDLE = 0 as _;
    let open_res = unsafe {
        FwpmEngineOpen0(
            std::ptr::null(),
            0xFFFFFFFF,
            std::ptr::null(),
            std::ptr::null(),
            &mut reader_handle,
        )
    };
    assert_eq!(open_res, 0, "Independent FwpmEngineOpen0 must succeed");

    // 3. Verify each filter exists in WFP and verify weights and sublayer
    for &id in &filter_ids {
        let mut filter_ptr: *mut FWPM_FILTER0 = std::ptr::null_mut();
        let get_res = unsafe { FwpmFilterGetById0(reader_handle, id, &mut filter_ptr) };
        assert_eq!(
            get_res, 0,
            "Filter {} must be retrievable from real WFP engine",
            id
        );
        assert!(!filter_ptr.is_null());
        unsafe {
            let filter = &*filter_ptr;
            assert_eq!(filter.filterId, id);
            assert_eq!(filter.subLayerKey.data1, FWPM_SUBLAYER_UNIVERSAL.data1);
            assert_eq!(filter.subLayerKey.data2, FWPM_SUBLAYER_UNIVERSAL.data2);
            assert_eq!(filter.subLayerKey.data3, FWPM_SUBLAYER_UNIVERSAL.data3);
            assert_eq!(filter.subLayerKey.data4, FWPM_SUBLAYER_UNIVERSAL.data4);
            let mut ptr_to_free = filter_ptr as *mut std::ffi::c_void;
            FwpmFreeMemory0(&mut ptr_to_free);
        }
    }

    // 4. Remove killswitch through backend
    backend
        .remove_kill_switch(&filter_ids)
        .expect("Remove real WFP filters");

    // 5. Verify through the second session that every filter is now gone
    const FWP_E_FILTER_NOT_FOUND: u32 = 0x80320003;
    for &id in &filter_ids {
        let mut filter_ptr: *mut FWPM_FILTER0 = std::ptr::null_mut();
        let get_res = unsafe { FwpmFilterGetById0(reader_handle, id, &mut filter_ptr) };
        assert_eq!(
            get_res, FWP_E_FILTER_NOT_FOUND,
            "Filter {} must be deleted and not found after removal",
            id
        );
    }

    unsafe {
        let _ = FwpmEngineClose0(reader_handle);
    }
}

#[cfg(windows)]
#[test]
#[ignore = "requires admin: writes real WFP filters"]

fn test_real_windows_wfp_dynamic_session_automatic_reaping() {
    use ifoxy_windows::vpn::killswitch::{FirewallBackend, WindowsFirewallBackend};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    let policy = KillSwitchPolicy {
        kill_switch_enabled: true,
        block_ipv6_leaks: true,
        edge_ip: Some(Ipv4Addr::new(151, 101, 1, 140)),
        wintun_if_index: Some(42),
        wintun_local_ip: Some(Ipv4Addr::new(10, 254, 1, 1)),
    };

    let mut reader_handle: HANDLE = 0 as _;
    let open_res = unsafe {
        FwpmEngineOpen0(
            std::ptr::null(),
            0xFFFFFFFF,
            std::ptr::null(),
            std::ptr::null(),
            &mut reader_handle,
        )
    };
    assert_eq!(open_res, 0);

    let filter_ids = {
        let backend = WindowsFirewallBackend::new();
        let ids = backend
            .install_kill_switch(&policy)
            .expect("Install dynamic filters");

        // Verify filters are alive while session is open
        for &id in &ids {
            let mut filter_ptr: *mut FWPM_FILTER0 = std::ptr::null_mut();
            let get_res = unsafe { FwpmFilterGetById0(reader_handle, id, &mut filter_ptr) };
            assert_eq!(get_res, 0);
            unsafe {
                let mut ptr_to_free = filter_ptr as *mut std::ffi::c_void;
                FwpmFreeMemory0(&mut ptr_to_free);
            }
        }

        // Backend is dropped here without calling remove_kill_switch.
        // Its dynamic session is closed.
        ids
    };

    // BFE must automatically reap every filter installed in the dynamic session
    const FWP_E_FILTER_NOT_FOUND: u32 = 0x80320003;
    for &id in &filter_ids {
        let mut filter_ptr: *mut FWPM_FILTER0 = std::ptr::null_mut();
        let get_res = unsafe { FwpmFilterGetById0(reader_handle, id, &mut filter_ptr) };
        assert_eq!(
            get_res, FWP_E_FILTER_NOT_FOUND,
            "BFE must automatically reap filter {} when dynamic session closes",
            id
        );
    }

    unsafe {
        let _ = FwpmEngineClose0(reader_handle);
    }
}

/// Stronger read-back than "the filter exists": checks, through an
/// independent WFP session, the layer, action, weight and the actual
/// condition values of every installed filter, and that every PERMIT
/// outranks the catch-all BLOCK on the same layer.
///
/// This still does not prove that packets are really blocked or permitted;
/// that needs the packet-capture procedure in docs/TESTING.md.
#[cfg(windows)]
#[test]
#[ignore = "requires admin: writes real WFP filters"]

fn test_real_windows_wfp_filter_semantics_readback() {
    use ifoxy_windows::vpn::killswitch::{FirewallBackend, WindowsFirewallBackend};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    fn guid_eq(a: &GUID, b: &GUID) -> bool {
        a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
    }

    unsafe fn wide_to_string(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }

    let edge = Ipv4Addr::new(151, 101, 1, 140);
    let local = Ipv4Addr::new(10, 254, 1, 1);
    let policy = KillSwitchPolicy {
        kill_switch_enabled: true,
        block_ipv6_leaks: true,
        edge_ip: Some(edge),
        wintun_if_index: Some(42),
        wintun_local_ip: Some(local),
    };

    let backend = WindowsFirewallBackend::new();
    let ids = backend
        .install_kill_switch(&policy)
        .expect("Install real WFP filters");

    let mut reader: HANDLE = 0 as _;
    let open_res = unsafe {
        FwpmEngineOpen0(
            std::ptr::null(),
            0xFFFFFFFF,
            std::ptr::null(),
            std::ptr::null(),
            &mut reader,
        )
    };
    assert_eq!(open_res, 0, "Independent FwpmEngineOpen0 must succeed");

    // (name, is_v6, is_permit, weight, number_of_conditions)
    let expected: [(&str, bool, bool, u8, u32); 7] = [
        ("iFoxy_KillSwitch_Permit_Loopback_V4", false, true, 15, 1),
        ("iFoxy_KillSwitch_Permit_DHCP", false, true, 14, 2),
        ("iFoxy_KillSwitch_Permit_Edge", false, true, 13, 1),
        ("iFoxy_KillSwitch_Permit_Tunnel", false, true, 12, 1),
        ("iFoxy_KillSwitch_Block_All_V4", false, false, 0, 0),
        ("iFoxy_KillSwitch_Permit_Loopback_V6", true, true, 15, 1),
        ("iFoxy_Block_IPv6_Leak", true, false, 0, 0),
    ];

    let mut seen: Vec<String> = Vec::new();
    let mut v4_block_weight: Option<u8> = None;
    let mut v4_min_permit_weight: u8 = u8::MAX;

    for &id in &ids {
        let mut fptr: *mut FWPM_FILTER0 = std::ptr::null_mut();
        let res = unsafe { FwpmFilterGetById0(reader, id, &mut fptr) };
        assert_eq!(res, 0, "Filter {} must be retrievable", id);
        assert!(!fptr.is_null());

        unsafe {
            let f = &*fptr;
            let name = wide_to_string(f.displayData.name);
            let (_, is_v6, is_permit, weight, n_conds) = *expected
                .iter()
                .find(|e| e.0 == name)
                .unwrap_or_else(|| panic!("Unexpected filter installed: {}", name));

            let layer_ok = if is_v6 {
                guid_eq(&f.layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V6)
            } else {
                guid_eq(&f.layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4)
            };
            assert!(layer_ok, "{}: wrong layer", name);
            assert!(
                guid_eq(&f.subLayerKey, &FWPM_SUBLAYER_UNIVERSAL),
                "{}: wrong sublayer",
                name
            );

            let want_action = if is_permit {
                FWP_ACTION_PERMIT
            } else {
                FWP_ACTION_BLOCK
            };
            assert_eq!(f.action.r#type, want_action, "{}: wrong action", name);
            assert_eq!(f.weight.r#type, FWP_UINT8, "{}: weight type", name);
            assert_eq!(f.weight.Anonymous.uint8, weight, "{}: wrong weight", name);
            assert_eq!(f.numFilterConditions, n_conds, "{}: condition count", name);

            let conds: &[FWPM_FILTER_CONDITION0] = if n_conds == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(f.filterCondition, n_conds as usize)
            };
            let find = |key: &GUID| conds.iter().find(|c| guid_eq(&c.fieldKey, key));

            match name.as_str() {
                "iFoxy_KillSwitch_Permit_Edge" => {
                    let c = find(&FWPM_CONDITION_IP_REMOTE_ADDRESS).expect("remote address cond");
                    assert_eq!(c.matchType, FWP_MATCH_EQUAL);
                    assert_eq!(c.conditionValue.r#type, FWP_UINT32);
                    assert_eq!(c.conditionValue.Anonymous.uint32, u32::from(edge));
                }
                "iFoxy_KillSwitch_Permit_Tunnel" => {
                    let c = find(&FWPM_CONDITION_IP_LOCAL_ADDRESS).expect("local address cond");
                    assert_eq!(c.matchType, FWP_MATCH_EQUAL);
                    assert_eq!(c.conditionValue.r#type, FWP_UINT32);
                    assert_eq!(c.conditionValue.Anonymous.uint32, u32::from(local));
                }
                "iFoxy_KillSwitch_Permit_DHCP" => {
                    let proto = find(&FWPM_CONDITION_IP_PROTOCOL).expect("protocol cond");
                    assert_eq!(proto.conditionValue.r#type, FWP_UINT8);
                    assert_eq!(proto.conditionValue.Anonymous.uint8, 17);
                    let port = find(&FWPM_CONDITION_IP_REMOTE_PORT).expect("port cond");
                    assert_eq!(port.conditionValue.r#type, FWP_UINT16);
                    assert_eq!(port.conditionValue.Anonymous.uint16, 67);
                }
                "iFoxy_KillSwitch_Permit_Loopback_V4"
                | "iFoxy_KillSwitch_Permit_Loopback_V6" => {
                    let c = find(&FWPM_CONDITION_FLAGS).expect("flags cond");
                    assert_eq!(c.matchType, FWP_MATCH_FLAGS_ALL_SET);
                    assert_eq!(
                        c.conditionValue.Anonymous.uint32,
                        FWP_CONDITION_FLAG_IS_LOOPBACK
                    );
                }
                _ => {}
            }

            if !is_v6 {
                if is_permit {
                    v4_min_permit_weight = v4_min_permit_weight.min(weight);
                } else {
                    v4_block_weight = Some(weight);
                }
            }
            seen.push(name);

            let mut to_free = fptr as *mut std::ffi::c_void;
            FwpmFreeMemory0(&mut to_free);
        }
    }

    // Every expected filter was installed exactly once.
    for e in expected.iter() {
        assert_eq!(
            seen.iter().filter(|n| n.as_str() == e.0).count(),
            1,
            "filter {} must be installed exactly once",
            e.0
        );
    }
    // WFP evaluates higher weights first: all permits must outrank the block.
    assert!(
        v4_min_permit_weight > v4_block_weight.expect("v4 block filter"),
        "every IPv4 permit filter must have a higher weight than the block-all filter"
    );

    backend
        .remove_kill_switch(&ids)
        .expect("Remove real WFP filters");
    unsafe {
        let _ = FwpmEngineClose0(reader);
    }
}
