use crate::vpn::iphlpapi::{native_create_ip_forward_entry, native_delete_ip_forward_entry};
use crate::vpn::registry::{ProxySettingsBackup, WinRegistry};
use crate::vpn::routing::{RouteDefinition, RouteError};
use crate::vpn::system_proxy::notify_system_settings_changed;
use std::net::Ipv4Addr;
#[cfg(any(test, feature = "test-doubles"))]
use std::sync::{Arc, Mutex};

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
pub struct WindowsNativeBackend;

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

impl Default for WindowsNativeBackend {
    fn default() -> Self {
        Self::new()
    }
}

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
        // https= and socks= only: plain http:// is rejected by the local proxy
        // (501), so it must not be advertised (S-9).
        let proxy_server = format!("https=127.0.0.1:{port};socks=127.0.0.1:{port}");
        WinRegistry::write_internet_dword("ProxyEnable", 1)?;
        WinRegistry::write_internet_string("ProxyServer", &proxy_server)?;
        notify_system_settings_changed();
        Ok(())
    }

    fn restore_system_proxy(&self, backup: Option<&ProxySettingsBackup>) -> Result<(), String> {
        if let Some(b) = backup {
            WinRegistry::restore_proxy_settings(b)?;
        } else {
            WinRegistry::write_internet_dword("ProxyEnable", 0)?;
        }
        notify_system_settings_changed();
        Ok(())
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
