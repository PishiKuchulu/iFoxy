#[cfg(windows)]
use crate::vpn::iphlpapi::{native_create_ip_forward_entry, native_delete_ip_forward_entry};
#[cfg(windows)]
use crate::vpn::routing::{RouteDefinition, RouteError};
#[cfg(not(windows))]
use crate::vpn::routing::{RouteDefinition, RouteError};
#[cfg(windows)]
use crate::vpn::registry::ProxySettingsBackup;
#[cfg(target_os = "linux")]
use crate::vpn::system_proxy::ProxySettingsBackup;
use std::net::Ipv4Addr;
use std::sync::Arc;
#[cfg(any(test, feature = "test-doubles"))]
use std::sync::Mutex;

/// The production network backend for the current OS.
pub fn platform_backend() -> Arc<dyn NetworkBackend> {
    #[cfg(windows)]
    {
        Arc::new(WindowsNativeBackend::new())
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(LinuxNativeBackend::new())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        compile_error!("iFoxy desktop supports Windows and Linux only");
    }
}

pub trait NetworkBackend: Send + Sync {
    fn detect_default_gateway(&self) -> Result<Ipv4Addr, RouteError>;
    fn detect_default_gateway_and_interface(&self) -> Result<(Ipv4Addr, u32), RouteError> {
        let gw = self.detect_default_gateway()?;
        Ok((gw, 0))
    }
    fn add_route(&self, route: &RouteDefinition, if_index: u32) -> Result<(), RouteError>;
    fn delete_route(&self, route: &RouteDefinition, if_index: u32) -> Result<(), RouteError>;
    fn set_system_proxy(&self, port: u16) -> Result<(), String>;
    fn restore_system_proxy(&self, backup: Option<&ProxySettingsBackup>) -> Result<(), String>;
}

/// Production network backend using native Windows IP Helper & Registry APIs (M4, H3).
#[cfg(windows)]
pub struct WindowsNativeBackend;

#[cfg(windows)]
impl WindowsNativeBackend {
    pub fn new() -> Self {
        Self
    }

    fn prefix_to_mask(prefix_len: u8) -> Ipv4Addr {
        match prefix_len {
            0 => Ipv4Addr::new(0, 0, 0, 0),
            1 => Ipv4Addr::new(128, 0, 0, 0),
            8 => Ipv4Addr::new(255, 0, 0, 0),
            16 => Ipv4Addr::new(255, 255, 0, 0),
            24 => Ipv4Addr::new(255, 255, 255, 0),
            32 => Ipv4Addr::new(255, 255, 255, 255),
            _ => {
                let mask: u32 = if prefix_len == 0 {
                    0
                } else {
                    !((1 << (32 - prefix_len)) - 1)
                };
                Ipv4Addr::from(mask)
            }
        }
    }
}

/// Adds or deletes a route through `netsh interface ipv4`. Used as a fallback
/// when the IP Helper row API rejects a route. Requires administrator rights.
#[cfg(windows)]
fn netsh_route(
    action: &str,
    dest: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
    if_index: u32,
    metric: Option<u32>,
) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let prefix = format!("prefix={}/{}", dest, prefix_len);
    let iface = format!("interface={}", if_index);
    let nexthop = format!("nexthop={}", gateway);
    let mut args: Vec<String> = vec![
        "interface".into(),
        "ipv4".into(),
        action.into(),
        "route".into(),
        prefix,
        iface,
        nexthop,
    ];
    if let Some(m) = metric {
        args.push(format!("metric={}", m));
    }
    args.push("store=active".into());

    let out = std::process::Command::new("netsh")
        .args(&args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

#[cfg(not(windows))]
fn netsh_route(
    _action: &str,
    _dest: Ipv4Addr,
    _prefix_len: u8,
    _gateway: Ipv4Addr,
    _if_index: u32,
    _metric: Option<u32>,
) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
impl Default for WindowsNativeBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl NetworkBackend for WindowsNativeBackend {
    fn detect_default_gateway_and_interface(&self) -> Result<(Ipv4Addr, u32), RouteError> {
        // Native IP Helper API (0ms, zero shell subprocesses)
        if let Ok((gw, if_idx)) =
            crate::vpn::iphlpapi::native_get_best_route(Ipv4Addr::new(8, 8, 8, 8))
        {
            if !gw.is_unspecified() && !gw.is_loopback() {
                return Ok((gw, if_idx));
            }
        }

        Err(RouteError::CommandFailed(
            "Could not detect physical default gateway and interface via IP Helper.".into(),
        ))
    }

    fn detect_default_gateway(&self) -> Result<Ipv4Addr, RouteError> {
        self.detect_default_gateway_and_interface()
            .map(|(gw, _)| gw)
    }

    fn add_route(&self, route: &RouteDefinition, if_index: u32) -> Result<(), RouteError> {
        let mask = Self::prefix_to_mask(route.prefix_len);

        tracing::info!(
            "Adding route {}/{} via {} on interface index {} (metric {})",
            route.destination,
            route.prefix_len,
            route.gateway,
            if_index,
            route.metric
        );

        match native_create_ip_forward_entry(
            route.destination,
            mask,
            route.gateway,
            if_index,
            route.metric,
        ) {
            Ok(()) => Ok(()),
            Err(err_code) => {
                // The IP Helper row API can reject a valid route with
                // ERROR_BAD_ARGUMENTS (160). Retry through netsh, which uses a
                // different code path in Windows.
                tracing::warn!(
                    "IP Helper add route failed (Win32 {}); trying netsh fallback",
                    err_code
                );
                netsh_route(
                    "add",
                    route.destination,
                    route.prefix_len,
                    route.gateway,
                    if_index,
                    Some(route.metric),
                )
                .map_err(|netsh_err| {
                    RouteError::CommandFailed(format!(
                        "Failed to add route to {}/{} via {}: Win32 error {} (netsh: {})",
                        route.destination, route.prefix_len, route.gateway, err_code, netsh_err
                    ))
                })
            }
        }
    }

    fn delete_route(&self, route: &RouteDefinition, if_index: u32) -> Result<(), RouteError> {
        let mask = Self::prefix_to_mask(route.prefix_len);

        match native_delete_ip_forward_entry(route.destination, mask, route.gateway, if_index) {
            Ok(()) => Ok(()),
            Err(err_code) => {
                // The route may have been added through the netsh fallback, so
                // remove it the same way.
                netsh_route(
                    "delete",
                    route.destination,
                    route.prefix_len,
                    route.gateway,
                    if_index,
                    None,
                )
                .map_err(|netsh_err| {
                    RouteError::CommandFailed(format!(
                        "Failed to delete route to {}/{} via {}: Win32 error {} (netsh: {})",
                        route.destination, route.prefix_len, route.gateway, err_code, netsh_err
                    ))
                })
            }
        }
    }

    fn set_system_proxy(&self, port: u16) -> Result<(), String> {
        crate::vpn::system_proxy::apply_system_proxy(port)
    }

    fn restore_system_proxy(&self, backup: Option<&ProxySettingsBackup>) -> Result<(), String> {
        crate::vpn::system_proxy::restore_system_proxy(backup)
    }
}

/// Production network backend for Linux: the default gateway comes from
/// /proc/net/route, route changes go through iproute2 (`ip route`), and
/// the system proxy delegates to the per-OS store in `system_proxy`
/// (GNOME `gsettings`).
#[cfg(target_os = "linux")]
pub struct LinuxNativeBackend;

/// Interface name for an ifindex, from /sys/class/net (Linux only).
#[cfg(target_os = "linux")]
pub(crate) fn if_name_of_index(if_index: u32) -> Option<String> {
    let rd = std::fs::read_dir("/sys/class/net").ok()?;
    for entry in rd.flatten() {
        if let Ok(text) = std::fs::read_to_string(entry.path().join("ifindex")) {
            if text.trim().parse::<u32>().ok() == Some(if_index) {
                return Some(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
impl LinuxNativeBackend {
    pub fn new() -> Self {
        Self
    }

    fn if_name_of(if_index: u32) -> Option<String> {
        if_name_of_index(if_index)
    }

    fn ip_route(
        &self,
        action: &str,
        route: &RouteDefinition,
        if_index: u32,
        with_gateway: bool,
    ) -> Result<(), RouteError> {
        let dev = Self::if_name_of(if_index).ok_or_else(|| {
            RouteError::CommandFailed(format!("no interface with index {}", if_index))
        })?;
        let dest = format!("{}/{}", route.destination, route.prefix_len);
        let mut args: Vec<String> = vec!["route".into(), action.into(), dest];
        if with_gateway {
            args.push("via".into());
            args.push(route.gateway.to_string());
        }
        args.push("dev".into());
        args.push(dev);
        args.push("metric".into());
        args.push(route.metric.to_string());
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let out = std::process::Command::new("ip")
            .args(&arg_refs)
            .output()
            .map_err(|e| RouteError::CommandFailed(format!("failed to run ip: {}", e)))?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(RouteError::CommandFailed(format!(
            "ip {} failed: {}",
            arg_refs.join(" "),
            stderr
        )))
    }
}

#[cfg(target_os = "linux")]
impl Default for LinuxNativeBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl NetworkBackend for LinuxNativeBackend {
    fn detect_default_gateway_and_interface(&self) -> Result<(Ipv4Addr, u32), RouteError> {
        let table = std::fs::read_to_string("/proc/net/route").map_err(|e| {
            RouteError::CommandFailed(format!("cannot read /proc/net/route: {}", e))
        })?;
        let mut best: Option<(Ipv4Addr, String, u32)> = None;
        for line in table.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 8 || cols[1] != "00000000" {
                continue;
            }
            let gw_le = u32::from_str_radix(cols[2], 16).unwrap_or(0);
            if gw_le == 0 {
                continue;
            }
            let metric = cols[6].parse::<u32>().unwrap_or(u32::MAX);
            if best.as_ref().map(|(_, _, m)| metric < *m).unwrap_or(true) {
                best = Some((Ipv4Addr::from(gw_le.swap_bytes()), cols[0].to_string(), metric));
            }
        }
        let (gw, iface, _) = best.ok_or_else(|| {
            RouteError::CommandFailed("no default route found in /proc/net/route".into())
        })?;
        let if_index = std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", iface))
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok())
            .unwrap_or(0);
        Ok((gw, if_index))
    }

    fn detect_default_gateway(&self) -> Result<Ipv4Addr, RouteError> {
        self.detect_default_gateway_and_interface().map(|(gw, _)| gw)
    }

    fn add_route(&self, route: &RouteDefinition, if_index: u32) -> Result<(), RouteError> {
        // Prefer the gateway form. The TUN split routes name the tunnel's
        // own address as the gateway, which some kernels reject as a
        // nexthop; fall back to the device-only form every TUN client uses.
        match self.ip_route("add", route, if_index, true) {
            Ok(()) => Ok(()),
            Err(first) => self.ip_route("add", route, if_index, false).map_err(|_| first),
        }
    }

    fn delete_route(&self, route: &RouteDefinition, if_index: u32) -> Result<(), RouteError> {
        match self.ip_route("del", route, if_index, true) {
            Ok(()) => Ok(()),
            Err(_) => self.ip_route("del", route, if_index, false),
        }
    }

    fn set_system_proxy(&self, port: u16) -> Result<(), String> {
        crate::vpn::system_proxy::apply_system_proxy(port)
    }

    fn restore_system_proxy(&self, backup: Option<&ProxySettingsBackup>) -> Result<(), String> {
        crate::vpn::system_proxy::restore_system_proxy(backup)
    }
}

/// In-memory mock network backend for deterministic unit and integration tests.
#[cfg(any(test, feature = "test-doubles"))]
pub struct MockNetworkBackend {
    pub default_gateway: Ipv4Addr,
    pub installed_routes: Arc<Mutex<Vec<(RouteDefinition, u32)>>>,
    pub deleted_routes: Arc<Mutex<Vec<(RouteDefinition, u32)>>>,
    pub proxy_enabled_port: Arc<Mutex<Option<u16>>>,
}

#[cfg(any(test, feature = "test-doubles"))]
impl MockNetworkBackend {
    pub fn new(default_gateway: Ipv4Addr) -> Self {
        Self {
            default_gateway,
            installed_routes: Arc::new(Mutex::new(Vec::new())),
            deleted_routes: Arc::new(Mutex::new(Vec::new())),
            proxy_enabled_port: Arc::new(Mutex::new(None)),
        }
    }

    pub fn installed_count(&self) -> usize {
        self.installed_routes.lock().unwrap().len()
    }

    pub fn deleted_count(&self) -> usize {
        self.deleted_routes.lock().unwrap().len()
    }
}

#[cfg(any(test, feature = "test-doubles"))]
impl NetworkBackend for MockNetworkBackend {
    fn detect_default_gateway(&self) -> Result<Ipv4Addr, RouteError> {
        Ok(self.default_gateway)
    }

    fn add_route(&self, route: &RouteDefinition, if_index: u32) -> Result<(), RouteError> {
        self.installed_routes
            .lock()
            .unwrap()
            .push((route.clone(), if_index));
        Ok(())
    }

    fn delete_route(&self, route: &RouteDefinition, if_index: u32) -> Result<(), RouteError> {
        let mut installed = self.installed_routes.lock().unwrap();
        if let Some(pos) = installed
            .iter()
            .position(|(r, idx)| r == route && *idx == if_index)
        {
            installed.remove(pos);
        }
        self.deleted_routes
            .lock()
            .unwrap()
            .push((route.clone(), if_index));
        Ok(())
    }

    fn set_system_proxy(&self, port: u16) -> Result<(), String> {
        *self.proxy_enabled_port.lock().unwrap() = Some(port);
        Ok(())
    }

    fn restore_system_proxy(&self, _backup: Option<&ProxySettingsBackup>) -> Result<(), String> {
        *self.proxy_enabled_port.lock().unwrap() = None;
        Ok(())
    }
}
