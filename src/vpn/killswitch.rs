use crate::vpn::recovery_journal::RecoveryJournal;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

pub const IFOXY_WFP_PROVIDER_NAME: &str = "iFoxyKillSwitch";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchPolicy {
    pub kill_switch_enabled: bool,
    pub block_ipv6_leaks: bool,
    pub edge_ip: Option<Ipv4Addr>,
    pub wintun_if_index: Option<u32>,
    /// The tunnel adapter's assigned local IPv4 address (e.g. 10.254.1.1).
    /// The real WFP backend permits outbound traffic sourced from this
    /// address instead of matching on the interface LUID, to avoid an
    /// extra IfIndex-to-LUID conversion call. Required (alongside
    /// `wintun_if_index`) for the PermitTunnel rule to be installed.
    pub wintun_local_ip: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WfpRuleType {
    PermitLoopback,
    PermitDhcp,
    PermitEdge,
    PermitTunnel,
    BlockOutboundV4,
    BlockOutboundV6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WfpRuleDefinition {
    pub filter_id: u64,
    pub rule_type: WfpRuleType,
    pub weight: u8,
    pub description: String,
}

pub trait FirewallBackend: Send + Sync {
    fn install_kill_switch(&self, policy: &KillSwitchPolicy) -> Result<Vec<u64>, String>;
    fn remove_kill_switch(&self, filter_ids: &[u64]) -> Result<(), String>;
}

/// Native Windows Filtering Platform (WFP) backend using dynamic session (R-8)
pub struct WindowsFirewallBackend {
    #[cfg(windows)]
    engine_handle: Mutex<Option<windows_sys::Win32::Foundation::HANDLE>>,
}

impl WindowsFirewallBackend {
    pub fn new() -> Self {
        Self {
            #[cfg(windows)]
            engine_handle: Mutex::new(None),
        }
    }
}

impl Default for WindowsFirewallBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallBackend for WindowsFirewallBackend {
    fn install_kill_switch(&self, policy: &KillSwitchPolicy) -> Result<Vec<u64>, String> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

            let session = FWPM_SESSION0 {
                flags: FWPM_SESSION_FLAG_DYNAMIC,
                txnWaitTimeoutInMSec: 5000,
                processId: std::process::id(),
                ..unsafe { std::mem::zeroed() }
            };

            const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFFFFFF;
            let mut handle: HANDLE = 0 as _;
            let res = unsafe {
                FwpmEngineOpen0(
                    std::ptr::null(),
                    RPC_C_AUTHN_DEFAULT,
                    std::ptr::null(),
                    &session,
                    &mut handle,
                )
            };

            if res != 0 {
                return Err(format!("FwpmEngineOpen0 failed: 0x{:08X}", res));
            }

            *self.engine_handle.lock().unwrap() = Some(handle);

            // Real filters, added in a dynamic session so BFE (the Base
            // Filtering Engine) automatically reaps every one of them if
            // this process dies or the handle is otherwise lost, without
            // depending on our own cleanup code running (S-1, S-6).
            //
            // SAFETY: every call below is a synchronous WFP API call; all
            // pointers passed (condition arrays, wide-string buffers, the
            // interface-LUID value) are kept alive on the stack for the
            // duration of the call that uses them and are not retained by
            // the kernel afterwards.
            let result = unsafe { wfp::install_filters(handle, policy) };
            match result {
                Ok(ids) => Ok(ids),
                Err(e) => {
                    // Roll back whatever partial set of filters we did
                    // manage to add before closing the handle, so a failed
                    // apply() never leaves half a kill switch in place.
                    unsafe {
                        let _ = FwpmEngineClose0(handle);
                    }
                    *self.engine_handle.lock().unwrap() = None;
                    Err(e)
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = policy;
            Err("WFP is only supported on Windows".into())
        }
    }

    fn remove_kill_switch(&self, filter_ids: &[u64]) -> Result<(), String> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

            let mut lock = self.engine_handle.lock().unwrap();
            if let Some(handle) = lock.take() {
                for &id in filter_ids {
                    unsafe {
                        let _ = FwpmFilterDeleteById0(handle, id);
                    }
                }
                unsafe {
                    let _ = FwpmEngineClose0(handle);
                }
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = filter_ids;
            Ok(())
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsFirewallBackend {
    fn drop(&mut self) {
        if let Ok(mut lock) = self.engine_handle.lock() {
            if let Some(handle) = lock.take() {
                // SAFETY: handle is a valid, open WFP engine handle owned by this struct.
                // Closing it terminates the dynamic session, causing BFE to automatically
                // reap all installed filters.
                unsafe {
                    let _ = windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0(handle);
                }
            }
        }
    }
}

/// Builds and installs the real set of WFP filters (S-1 in the round-3
/// review: the previous implementation opened a WFP session and then
/// returned hard-coded synthetic filter IDs without ever calling
/// `FwpmFilterAdd0`, so nothing was actually blocked).
///
/// Filters are added directly to the built-in universal sublayer
/// (`FWPM_SUBLAYER_UNIVERSAL`) at the ALE_AUTH_CONNECT layer, which is
/// evaluated once per outbound connection attempt before it is allowed to
/// proceed. Within one sublayer, WFP evaluates filters from the highest
/// `weight` to the lowest and stops at the first matching terminating
/// action (PERMIT/BLOCK are both terminating), so every PERMIT filter here
/// uses a higher weight than the catch-all BLOCK filter and is therefore
/// evaluated first.
///
/// NOT independently verified: the review environment has no Windows
/// machine and no Rust toolchain, so this code has been read carefully
/// against the public WFP API shape but never compiled. The single most
/// likely compile failure is the name of the anonymous union field inside
/// `FWP_CONDITION_VALUE0` / `FWP_VALUE0` / `FWPM_ACTION0` (written below as
/// `.Anonymous.<field>`, windows-sys's usual naming for an anonymous C
/// union) — if your installed windows-sys version names it differently,
/// that is the first thing to fix.
#[cfg(windows)]
mod wfp {
    use super::KillSwitchPolicy;
    use std::net::Ipv4Addr;
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    const IPPROTO_UDP: u8 = 17;

    fn wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn display_data(name: &mut Vec<u16>, desc: &mut Vec<u16>) -> FWPM_DISPLAY_DATA0 {
        FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: desc.as_mut_ptr(),
        }
    }

    fn value_u8(v: u8) -> FWP_VALUE0 {
        let mut value: FWP_VALUE0 = unsafe { std::mem::zeroed() };
        value.r#type = FWP_UINT8;
        value.Anonymous.uint8 = v;
        value
    }

    fn cond_u8(field: GUID, match_type: FWP_MATCH_TYPE, v: u8) -> FWPM_FILTER_CONDITION0 {
        let mut cv: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
        cv.r#type = FWP_UINT8;
        cv.Anonymous.uint8 = v;
        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: match_type,
            conditionValue: cv,
        }
    }

    fn cond_u16(field: GUID, match_type: FWP_MATCH_TYPE, v: u16) -> FWPM_FILTER_CONDITION0 {
        let mut cv: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
        cv.r#type = FWP_UINT16;
        cv.Anonymous.uint16 = v;
        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: match_type,
            conditionValue: cv,
        }
    }

    fn cond_u32(field: GUID, match_type: FWP_MATCH_TYPE, v: u32) -> FWPM_FILTER_CONDITION0 {
        let mut cv: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
        cv.r#type = FWP_UINT32;
        cv.Anonymous.uint32 = v;
        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: match_type,
            conditionValue: cv,
        }
    }

    /// Installs one filter and returns the real filter ID WFP assigned it.
    ///
    /// SAFETY: `conditions` must outlive this call (it is only read inside
    /// `FwpmFilterAdd0`, synchronously); `name`/`desc` wide-string buffers
    /// likewise must outlive it. All of this holds because every caller
    /// below keeps those buffers as local variables for the duration of
    /// the single `install_one` call that uses them.
    unsafe fn install_one(
        engine: HANDLE,
        layer: GUID,
        action: FWP_ACTION_TYPE,
        weight: u8,
        conditions: &[FWPM_FILTER_CONDITION0],
        name: &str,
        desc: &str,
    ) -> Result<u64, String> {
        let mut name_w = wide_null(name);
        let mut desc_w = wide_null(desc);

        let filter = FWPM_FILTER0 {
            filterKey: std::mem::zeroed(),
            displayData: display_data(&mut name_w, &mut desc_w),
            flags: 0,
            providerKey: std::ptr::null_mut(),
            providerData: std::mem::zeroed(),
            layerKey: layer,
            subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
            weight: value_u8(weight),
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                std::ptr::null_mut()
            } else {
                conditions.as_ptr() as *mut FWPM_FILTER_CONDITION0
            },
            action: FWPM_ACTION0 {
                r#type: action,
                Anonymous: FWPM_ACTION0_0 {
                    filterType: std::mem::zeroed(),
                },
            },
            Anonymous: std::mem::zeroed(),
            reserved: std::ptr::null_mut(),
            filterId: 0,
            effectiveWeight: std::mem::zeroed(),
        };

        let mut filter_id: u64 = 0;
        let res = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut filter_id);
        if res != 0 {
            return Err(format!(
                "FwpmFilterAdd0 failed for '{}': 0x{:08X}",
                name, res
            ));
        }
        Ok(filter_id)
    }

    /// Installs the full filter set described in `policy` and returns the
    /// real filter IDs (for later removal via `FwpmFilterDeleteById0`). On
    /// any failure, every filter already added in this call is rolled back
    /// before returning the error, so a failed `apply()` never leaves a
    /// partial, inconsistent kill switch behind.
    pub unsafe fn install_filters(
        engine: HANDLE,
        policy: &KillSwitchPolicy,
    ) -> Result<Vec<u64>, String> {
        let mut installed: Vec<u64> = Vec::new();

        macro_rules! add {
            ($layer:expr, $action:expr, $weight:expr, $conds:expr, $name:expr) => {
                match install_one(engine, $layer, $action, $weight, $conds, $name, $name) {
                    Ok(id) => installed.push(id),
                    Err(e) => {
                        for &id in &installed {
                            let _ = FwpmFilterDeleteById0(engine, id);
                        }
                        return Err(e);
                    }
                }
            };
        }

        if policy.kill_switch_enabled {
            // --- IPv4 ALE_AUTH_CONNECT layer ---
            add!(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWP_ACTION_PERMIT,
                15,
                &[cond_u32(
                    FWPM_CONDITION_FLAGS,
                    FWP_MATCH_FLAGS_ALL_SET,
                    FWP_CONDITION_FLAG_IS_LOOPBACK,
                )],
                "iFoxy_KillSwitch_Permit_Loopback_V4"
            );

            add!(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWP_ACTION_PERMIT,
                14,
                &[
                    cond_u8(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, IPPROTO_UDP),
                    cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, 67),
                ],
                "iFoxy_KillSwitch_Permit_DHCP"
            );

            if let Some(edge_ip) = policy.edge_ip {
                add!(
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    FWP_ACTION_PERMIT,
                    13,
                    &[cond_u32(
                        FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        FWP_MATCH_EQUAL,
                        ipv4_to_host_u32(edge_ip),
                    )],
                    "iFoxy_KillSwitch_Permit_Edge"
                );
            }

            if let Some(local_ip) = policy.wintun_local_ip {
                add!(
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    FWP_ACTION_PERMIT,
                    12,
                    &[cond_u32(
                        FWPM_CONDITION_IP_LOCAL_ADDRESS,
                        FWP_MATCH_EQUAL,
                        ipv4_to_host_u32(local_ip),
                    )],
                    "iFoxy_KillSwitch_Permit_Tunnel"
                );
            }

            add!(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWP_ACTION_BLOCK,
                0,
                &[],
                "iFoxy_KillSwitch_Block_All_V4"
            );
        }

        if policy.block_ipv6_leaks {
            // --- IPv6 ALE_AUTH_CONNECT layer: loopback stays permitted,
            // everything else is blocked outright since IPv6 traffic is
            // never routed through the tunnel today. ---
            add!(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWP_ACTION_PERMIT,
                15,
                &[cond_u32(
                    FWPM_CONDITION_FLAGS,
                    FWP_MATCH_FLAGS_ALL_SET,
                    FWP_CONDITION_FLAG_IS_LOOPBACK,
                )],
                "iFoxy_KillSwitch_Permit_Loopback_V6"
            );

            add!(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWP_ACTION_BLOCK,
                0,
                &[],
                "iFoxy_Block_IPv6_Leak"
            );
        }

        Ok(installed)
    }

    fn ipv4_to_host_u32(ip: Ipv4Addr) -> u32 {
        u32::from(ip)
    }
}

/// In-memory mock firewall backend for deterministic testing and fault injection (R-8)
#[cfg(any(test, feature = "test-doubles"))]
pub struct MockFirewallBackend {
    pub installed_rules: Arc<Mutex<Vec<String>>>,
    pub installed_definitions: Arc<Mutex<Vec<WfpRuleDefinition>>>,
    fail_at_step: Option<usize>,
}

#[cfg(any(test, feature = "test-doubles"))]
impl MockFirewallBackend {
    pub fn new() -> Self {
        Self {
            installed_rules: Arc::new(Mutex::new(Vec::new())),
            installed_definitions: Arc::new(Mutex::new(Vec::new())),
            fail_at_step: None,
        }
    }

    pub fn new_with_failure_at_step(step: usize) -> Self {
        Self {
            installed_rules: Arc::new(Mutex::new(Vec::new())),
            installed_definitions: Arc::new(Mutex::new(Vec::new())),
            fail_at_step: Some(step),
        }
    }

    pub fn get_installed_rule_definitions(&self) -> Vec<WfpRuleDefinition> {
        self.installed_definitions.lock().unwrap().clone()
    }

    pub fn installed_filter_count(&self) -> usize {
        self.installed_definitions.lock().unwrap().len()
    }
}

#[cfg(any(test, feature = "test-doubles"))]
impl Default for MockFirewallBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-doubles"))]
impl FirewallBackend for MockFirewallBackend {
    fn install_kill_switch(&self, policy: &KillSwitchPolicy) -> Result<Vec<u64>, String> {
        let mut candidates = Vec::new();
        let mut rule_strings = Vec::new();

        if policy.block_ipv6_leaks {
            candidates.push(WfpRuleDefinition {
                filter_id: 1001,
                rule_type: WfpRuleType::PermitLoopback,
                weight: 15,
                description: "iFoxy_WFP_Permit_Loopback_V6".into(),
            });
            candidates.push(WfpRuleDefinition {
                filter_id: 1002,
                rule_type: WfpRuleType::BlockOutboundV6,
                weight: 5,
                description: "iFoxy_Block_IPv6_Leak".into(),
            });
            rule_strings.push("iFoxy_Block_IPv6_Leak".to_string());
        }

        if policy.kill_switch_enabled {
            candidates.push(WfpRuleDefinition {
                filter_id: 2001,
                rule_type: WfpRuleType::PermitLoopback,
                weight: 15,
                description: "iFoxy_KillSwitch_Allow_Loopback".into(),
            });
            rule_strings.push("iFoxy_KillSwitch_Allow_Loopback".to_string());

            candidates.push(WfpRuleDefinition {
                filter_id: 2002,
                rule_type: WfpRuleType::PermitDhcp,
                weight: 14,
                description: "iFoxy_KillSwitch_Allow_DHCP".into(),
            });
            rule_strings.push("iFoxy_KillSwitch_Allow_DHCP".to_string());

            if policy.edge_ip.is_some() {
                candidates.push(WfpRuleDefinition {
                    filter_id: 2003,
                    rule_type: WfpRuleType::PermitEdge,
                    weight: 13,
                    description: "iFoxy_KillSwitch_Allow_Edge".into(),
                });
                rule_strings.push("iFoxy_KillSwitch_Allow_Edge".to_string());
            }

            if policy.wintun_if_index.is_some() {
                candidates.push(WfpRuleDefinition {
                    filter_id: 2004,
                    rule_type: WfpRuleType::PermitTunnel,
                    weight: 12,
                    description: "iFoxy_KillSwitch_Allow_Tunnel".into(),
                });
                rule_strings.push("iFoxy_KillSwitch_Allow_Tunnel".to_string());
            }

            candidates.push(WfpRuleDefinition {
                filter_id: 2005,
                rule_type: WfpRuleType::BlockOutboundV4,
                weight: 5,
                description: "iFoxy_KillSwitch_Block_All".into(),
            });
            rule_strings.push("iFoxy_KillSwitch_Block_All".to_string());
        }

        let mut installed = Vec::new();
        for (step, rule) in candidates.into_iter().enumerate() {
            if let Some(fail_step) = self.fail_at_step {
                if step == fail_step {
                    let ids_to_remove: Vec<u64> = installed
                        .iter()
                        .map(|r: &WfpRuleDefinition| r.filter_id)
                        .collect();
                    let _ = self.remove_kill_switch(&ids_to_remove);
                    return Err(format!("Injected failure at step {}", step));
                }
            }
            self.installed_definitions
                .lock()
                .unwrap()
                .push(rule.clone());
            installed.push(rule);
        }

        self.installed_rules.lock().unwrap().extend(rule_strings);
        Ok(installed.iter().map(|r| r.filter_id).collect())
    }

    fn remove_kill_switch(&self, filter_ids: &[u64]) -> Result<(), String> {
        let mut defs = self.installed_definitions.lock().unwrap();
        defs.retain(|d| !filter_ids.contains(&d.filter_id));
        let mut strings = self.installed_rules.lock().unwrap();
        strings.clear();
        for d in defs.iter() {
            strings.push(d.description.clone());
        }
        Ok(())
    }
}

pub struct KillSwitchGuard {
    backend: Arc<dyn FirewallBackend>,
    active_filters: Vec<u64>,
    active: Arc<AtomicBool>,
    journal: Option<RecoveryJournal>,
}

impl KillSwitchGuard {
    pub fn new(backend: Arc<dyn FirewallBackend>) -> Self {
        Self {
            backend,
            active_filters: Vec::new(),
            active: Arc::new(AtomicBool::new(false)),
            journal: None,
        }
    }

    pub fn new_with_journal(
        backend: Arc<dyn FirewallBackend>,
        journal: Option<RecoveryJournal>,
    ) -> Self {
        Self {
            backend,
            active_filters: Vec::new(),
            active: Arc::new(AtomicBool::new(false)),
            journal,
        }
    }

    pub fn apply(&mut self, policy: &KillSwitchPolicy) -> Result<(), String> {
        self.clean();
        let filters = self.backend.install_kill_switch(policy)?;

        if let Some(ref mut j) = self.journal {
            for &fid in &filters {
                j.record_wfp_filter(fid);
            }
            let _ = j.flush_to_disk();
        }

        self.active_filters = filters;
        self.active.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    pub fn clean(&mut self) {
        if self.active.load(Ordering::SeqCst) {
            let _ = self.backend.remove_kill_switch(&self.active_filters);
            self.active_filters.clear();
            self.active.store(false, Ordering::SeqCst);

            if let Some(ref j) = self.journal {
                j.mark_clean();
            }
        }
    }
}

impl Drop for KillSwitchGuard {
    fn drop(&mut self) {
        self.clean();
    }
}
