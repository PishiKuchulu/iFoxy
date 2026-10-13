use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use wintun::{Adapter, Session};

pub const DEFAULT_ADAPTER_NAME: &str = "iFoxy";
pub const DEFAULT_TUNNEL_TYPE: &str = "iFoxyTunnel";
pub const DEFAULT_WINTUN_IP: Ipv4Addr = Ipv4Addr::new(10, 254, 1, 1);
pub const FALLBACK_WINTUN_IP: Ipv4Addr = Ipv4Addr::new(172, 31, 254, 1);
pub const DEFAULT_WINTUN_NETMASK: &str = "255.255.255.0";

/// Stable deterministic GUID for iFoxy Wintun adapter (M5)
pub const IFOXY_ADAPTER_GUID: u128 = 0x6e8e2b80_4e28_4e09_b173_7b9d7e32c021;

/// Formats `IFOXY_ADAPTER_GUID` as a canonical Windows GUID string
/// ("XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", no braces). The registry key
/// under `Tcpip\Parameters\Interfaces\{...}` that controls per-adapter DNS
/// is keyed by this form of the GUID.
///
/// Previously `IFOXY_ADAPTER_GUID.to_string()` (plain `u128::to_string`)
/// was used directly, which prints the integer in **decimal**, not hex, and
/// has no hyphens at all. The resulting registry path never matched the
/// adapter's real GUID key, so the DNS server configured on the tunnel
/// interface was silently never applied (S-4 in the round-3 review).
pub fn format_adapter_guid(guid: u128) -> String {
    let hex = format!("{:032X}", guid);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// MTU 1420 prevents fragmentation over outer TLS/TCP transport (M5)
pub const VPN_ADAPTER_MTU: u32 = 1420;
/// TCP MSS clamped to MTU 1420 - 40 bytes IP/TCP headers (M5)
pub const VPN_TCP_MSS: u16 = 1380;

#[derive(Error, Debug)]
pub enum WintunError {
    #[error("Wintun driver error: {0}")]
    Driver(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration command failed: {0}")]
    ConfigFailed(String),
}

/// Address conflict check (M5): verify that preferred VPN subnet does not collide
/// with the physical gateway subnet. If collision occurs, returns an alternative subnet.
pub fn resolve_vpn_ip_avoiding_conflict(
    preferred_ip: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
) -> Ipv4Addr {
    if let Some(gw) = gateway {
        let pref_octets = preferred_ip.octets();
        let gw_octets = gw.octets();
        // Check if /24 matches
        if pref_octets[0] == gw_octets[0]
            && pref_octets[1] == gw_octets[1]
            && pref_octets[2] == gw_octets[2]
        {
            tracing::warn!(
                "Address conflict detected! Preferred VPN IP {} conflicts with gateway {}. Using fallback IP {}",
                preferred_ip,
                gw,
                FALLBACK_WINTUN_IP
            );
            return FALLBACK_WINTUN_IP;
        }
    }
    preferred_ip
}

pub const OFFICIAL_WINTUN_DLL_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
pub const EMBEDDED_WINTUN_DLL: &[u8] = include_bytes!("../../wintun.dll");

pub fn ensure_wintun_dll_at(target_dir: &std::path::Path) -> Result<PathBuf, WintunError> {
    let dll_name = "wintun.dll";
    let target_path = target_dir.join(dll_name);

    if target_path.exists() {
        // C3 & R-11: Cryptographically verify file hash before loading
        let bytes = fs::read(&target_path)?;
        let hash = crate::security::compute_sha256_hex(&bytes);
        if hash.eq_ignore_ascii_case(OFFICIAL_WINTUN_DLL_SHA256) {
            crate::security::verify_authenticode_signature(&target_path).map_err(|e| {
                WintunError::Driver(format!(
                    "wintun.dll Authenticode signature verification failed: {:?}",
                    e
                ))
            })?;
            return Ok(target_path);
        } else {
            return Err(WintunError::Driver(format!(
                "wintun.dll integrity verification failed! Expected hash {}, got {}. Refusing execution.",
                OFFICIAL_WINTUN_DLL_SHA256, hash
            )));
        }
    }

    // Write verified embedded binary
    crate::security::safe_write_and_verify(
        &target_path,
        EMBEDDED_WINTUN_DLL,
        OFFICIAL_WINTUN_DLL_SHA256,
    )
    .map_err(|e| WintunError::Driver(format!("Failed to write and verify wintun.dll: {:?}", e)))?;

    crate::security::verify_authenticode_signature(&target_path).map_err(|e| {
        WintunError::Driver(format!(
            "wintun.dll Authenticode signature verification failed: {:?}",
            e
        ))
    })?;

    Ok(target_path)
}

pub fn ensure_wintun_dll() -> Result<PathBuf, WintunError> {
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    ensure_wintun_dll_at(&exe_dir)
}

pub struct WintunDevice {
    pub adapter: Arc<Adapter>,
    pub session: Arc<Session>,
    pub adapter_index: u32,
    pub ip: Ipv4Addr,
}

/// Sets MTU and interface metric through `netsh`. Used only as a fallback when
/// the IP Helper API rejects the change. Requires administrator rights.
#[cfg(windows)]
fn set_mtu_metric_netsh(adapter_name: &str, mtu: u32, metric: u32) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let mtu_arg = format!("mtu={}", mtu);
    let out = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "subinterface",
            adapter_name,
            mtu_arg.as_str(),
            "store=active",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "set subinterface: {}",
            String::from_utf8_lossy(&out.stdout).trim()
        ));
    }

    let metric_arg = format!("metric={}", metric);
    let out = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "interface",
            adapter_name,
            metric_arg.as_str(),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "set interface metric: {}",
            String::from_utf8_lossy(&out.stdout).trim()
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_mtu_metric_netsh(_adapter_name: &str, _mtu: u32, _metric: u32) -> Result<(), String> {
    Ok(())
}

impl WintunDevice {
    pub fn create_or_open(name: &str, preferred_ip: Ipv4Addr) -> Result<Self, WintunError> {
        let dll_path = ensure_wintun_dll()?;
        let wintun = unsafe {
            wintun::load_from_path(&dll_path)
                .map_err(|e| WintunError::Driver(format!("Failed to load wintun.dll: {:?}", e)))?
        };

        // Check for address conflict against detected gateway
        let detected_gw = crate::vpn::routing::detect_default_gateway().ok();
        let assigned_ip = resolve_vpn_ip_avoiding_conflict(preferred_ip, detected_gw);

        // Open existing or create with deterministic stable GUID (M5)
        let adapter = match Adapter::open(&wintun, name) {
            Ok(a) => a,
            Err(_) => Adapter::create(
                &wintun,
                name,
                DEFAULT_TUNNEL_TYPE,
                Some(IFOXY_ADAPTER_GUID),
            )
            .map_err(|e| WintunError::Driver(format!("Failed to create adapter: {:?}", e)))?,
        };

        let adapter_index = adapter
            .get_adapter_index()
            .map_err(|e| WintunError::Driver(format!("Failed to get adapter index: {:?}", e)))?;

        // 1. Configure static IP on Wintun adapter using native IP Helper API (M4, M5, R-15)
        crate::vpn::iphlpapi::native_set_interface_ip_address(adapter_index, assigned_ip, 24)
            .map_err(|e| {
                WintunError::Driver(format!("IP Helper set interface IP failed: 0x{:08X}", e))
            })?;

        // 2. Configure MTU 1420 and interface metric 1 (M5, R-4).
        // This step is best-effort: the tunnel works without it, and some Windows
        // builds reject SetIpInterfaceEntry with ERROR_INVALID_PARAMETER (0x57).
        // Fall back to netsh, and if that also fails, log and continue.
        if let Err(e) = crate::vpn::iphlpapi::native_set_interface_metric_and_mtu(
            adapter_index,
            1,
            VPN_ADAPTER_MTU,
        ) {
            tracing::warn!(
                "IP Helper set MTU/metric failed (0x{:08X}); trying netsh fallback",
                e
            );
            if let Err(err) = set_mtu_metric_netsh(name, VPN_ADAPTER_MTU, 1) {
                tracing::warn!("netsh MTU/metric fallback also failed: {}", err);
            }
        }

        // 3. Configure primary DNS (1.1.1.1) on Wintun interface natively using SetInterfaceDnsSettings (R-4, S-4)
        crate::vpn::iphlpapi::native_set_interface_dns(adapter_index, Ipv4Addr::new(1, 1, 1, 1))
            .map_err(|e| {
                WintunError::Driver(format!("SetInterfaceDnsSettings failed: 0x{:08X}", e))
            })?;

        // Fallback registry backup for offline/reboot durability
        let _ = crate::vpn::iphlpapi::native_set_adapter_dns(
            &format_adapter_guid(IFOXY_ADAPTER_GUID),
            Ipv4Addr::new(1, 1, 1, 1),
        );

        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| WintunError::Driver(format!("Failed to start session: {:?}", e)))?;

        Ok(Self {
            adapter,
            session: Arc::new(session),
            adapter_index,
            ip: assigned_ip,
        })
    }
}
