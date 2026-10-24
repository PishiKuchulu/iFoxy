use crate::vpn::network_backend::{platform_backend, NetworkBackend};
use crate::vpn::recovery_journal::RecoveryJournal;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RouteError {
    #[error("Failed to execute route operation: {0}")]
    CommandFailed(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteDefinition {
    pub destination: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub metric: u32,
}

pub fn is_private_or_loopback(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 127.0.0.0/8 (loopback)
    if octets[0] == 127 {
        return true;
    }
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 169.254.0.0/16 (link local)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // Multicast (224.0.0.0/4) or Broadcast (255.255.255.255)
    if octets[0] >= 224 {
        return true;
    }
    // 0.0.0.0/8
    if octets[0] == 0 {
        return true;
    }
    false
}

pub fn split_tunnel_routes(gateway: Ipv4Addr) -> Vec<RouteDefinition> {
    vec![
        RouteDefinition {
            destination: Ipv4Addr::new(0, 0, 0, 0),
            prefix_len: 1,
            gateway,
            metric: 1,
        },
        RouteDefinition {
            destination: Ipv4Addr::new(128, 0, 0, 0),
            prefix_len: 1,
            gateway,
            metric: 1,
        },
    ]
}

pub fn detect_default_gateway() -> Result<Ipv4Addr, RouteError> {
    detect_default_gateway_and_interface().map(|(gw, _)| gw)
}

pub fn detect_default_gateway_and_interface() -> Result<(Ipv4Addr, u32), RouteError> {
    platform_backend().detect_default_gateway_and_interface()
}

#[cfg(windows)]
pub fn is_admin() -> bool {
    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
    }

    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(target_os = "linux")]
pub fn is_admin() -> bool {
    let uid = unsafe { libc::geteuid() };
    uid == 0
}

#[cfg(windows)]
pub fn request_elevation() {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: *mut std::ffi::c_void,
            operation: *const u16,
            file: *const u16,
            parameters: *const u16,
            directory: *const u16,
            show_cmd: i32,
        ) -> isize;
    }

    if let Ok(exe) = std::env::current_exe() {
        let exe_wide: Vec<u16> = exe
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let runas_wide: Vec<u16> = std::ffi::OsStr::new("runas")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                runas_wide.as_ptr(),
                exe_wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1, // SW_SHOWNORMAL
            );
        }
    }
}

/// Linux elevation: relaunch through pkexec (PolicyKit GUI prompt). The
/// `IFOXY_ELEVATION_TRIED` marker stops a relaunch loop when pkexec
/// exists but the user declines the prompt.
#[cfg(target_os = "linux")]
pub fn request_elevation() {
    if std::env::var("IFOXY_ELEVATION_TRIED").is_ok() {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        // pkexec scrubs the environment and would set HOME to root's,
        // which used to land the session file and recovery journal in
        // /root/.config/iFoxy while the docs promise the invoking
        // user's config dir (external review, H5). Pass the user's
        // session environment through explicitly: home/XDG dirs keep
        // state in the user's tree, and the display/bus variables give
        // the elevated GUI its session even on pkexec versions that do
        // not propagate them.
        let mut cmd = std::process::Command::new("pkexec");
        cmd.arg("env").arg("IFOXY_ELEVATION_TRIED=1");
        for var in [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "DBUS_SESSION_BUS_ADDRESS",
        ] {
            if let Ok(value) = std::env::var(var) {
                cmd.arg(format!("{}={}", var, value));
            }
        }
        match cmd.arg(&exe).args(&args).spawn() {
            Ok(_) => {},
            Err(e) => {
                eprintln!(
                    "iFoxy needs administrator rights for the TUN device and routes.\n\
                     Automatic elevation failed ({}). Install policykit (pkexec) or run:\n  sudo {}",
                    e,
                    exe.display()
                );
            }
        }
    }
}

/// Best route (gateway, ifindex) toward `target` on this OS, for the
/// network watcher. Windows uses the IP Helper API; Linux's default-route
/// lookup covers public targets such as the VPN edge.
pub fn platform_best_route(target: Ipv4Addr) -> Option<(Ipv4Addr, u32)> {
    #[cfg(windows)]
    {
        crate::vpn::iphlpapi::native_get_best_route(target).ok()
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        detect_default_gateway_and_interface().ok()
    }
}

/// Subscribe to OS route-change notifications where the platform offers
/// them (Windows NotifyRouteChange2). Linux returns None and the watcher
/// falls back to its polling interval. The returned value is an opaque
/// keep-alive handle for the subscription.
#[cfg(windows)]
pub fn platform_subscribe_route_changes(
    sender: tokio::sync::mpsc::Sender<()>,
) -> Option<crate::vpn::iphlpapi::RouteChangeSubscription> {
    crate::vpn::iphlpapi::subscribe_route_changes(sender).ok()
}

#[cfg(not(windows))]
pub fn platform_subscribe_route_changes(
    _sender: tokio::sync::mpsc::Sender<()>,
) -> Option<std::convert::Infallible> {
    None
}

pub struct RouteGuard {
    backend: Arc<dyn NetworkBackend>,
    installed_routes: Vec<RouteDefinition>,
    edge_bypass_route: Option<RouteDefinition>,
    physical_if_idx: u32,
    wintun_if_idx: u32,
    journal: Option<Arc<std::sync::Mutex<RecoveryJournal>>>,
}

impl RouteGuard {
    pub fn new(
        installed_routes: Vec<RouteDefinition>,
        edge_bypass_route: Option<RouteDefinition>,
        physical_if_idx: u32,
        wintun_if_idx: u32,
        backend: Arc<dyn NetworkBackend>,
        journal: Option<Arc<std::sync::Mutex<RecoveryJournal>>>,
    ) -> Self {
        Self {
            backend,
            installed_routes,
            edge_bypass_route,
            physical_if_idx,
            wintun_if_idx,
            journal,
        }
    }

    pub fn installed_routes(&self) -> &[RouteDefinition] {
        &self.installed_routes
    }

    pub fn edge_bypass_ip(&self) -> Option<Ipv4Addr> {
        self.edge_bypass_route.as_ref().map(|r| r.destination)
    }

    pub fn physical_if_idx(&self) -> u32 {
        self.physical_if_idx
    }

    pub fn wintun_if_idx(&self) -> u32 {
        self.wintun_if_idx
    }

    pub fn reapply_edge_bypass(
        &mut self,
        new_physical_gw: Ipv4Addr,
        new_physical_if_idx: u32,
    ) -> Result<(), RouteError> {
        if let Some(mut edge_route) = self.edge_bypass_route.take() {
            let _ = self.backend.delete_route(&edge_route, self.physical_if_idx);

            edge_route.gateway = new_physical_gw;
            self.backend.add_route(&edge_route, new_physical_if_idx)?;

            self.physical_if_idx = new_physical_if_idx;
            self.edge_bypass_route = Some(edge_route.clone());

            if let Some(ref j) = self.journal {
                if let Ok(mut j) = j.lock() {
                    j.record_edge_bypass(
                        edge_route.destination,
                        new_physical_gw,
                        new_physical_if_idx,
                    );
                    let _ = j.flush_to_disk();
                }
            }
        }
        Ok(())
    }

    pub fn clean(&mut self) {
        for route in &self.installed_routes {
            let _ = self.backend.delete_route(route, self.wintun_if_idx);
        }
        self.installed_routes.clear();

        if let Some(edge_route) = self.edge_bypass_route.take() {
            let _ = self.backend.delete_route(&edge_route, self.physical_if_idx);
        }

        if let Some(ref journal) = self.journal {
            if let Ok(mut j) = journal.lock() {
                j.clear_routes_and_bypass();
            }
        }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.clean();
    }
}

pub struct RouteManager;

impl RouteManager {
    pub fn install_vpn_routes(
        edge_ip: Ipv4Addr,
        physical_gateway: Ipv4Addr,
        physical_if_idx: u32,
        wintun_ip: Ipv4Addr,
        wintun_if_idx: u32,
    ) -> Result<RouteGuard, RouteError> {
        let backend = platform_backend();
        Self::install_vpn_routes_with_backend(
            edge_ip,
            physical_gateway,
            physical_if_idx,
            wintun_ip,
            wintun_if_idx,
            backend,
            true,
        )
    }

    pub fn install_vpn_routes_with_backend(
        edge_ip: Ipv4Addr,
        physical_gateway: Ipv4Addr,
        physical_if_idx: u32,
        wintun_ip: Ipv4Addr,
        wintun_if_idx: u32,
        backend: Arc<dyn NetworkBackend>,
        use_journal: bool,
    ) -> Result<RouteGuard, RouteError> {
        let journal = if use_journal {
            // The shared journal instance: proxy, kill switch and DNS
            // records live in the same file without overwriting each
            // other (external review, S6b).
            let j = RecoveryJournal::shared_default();
            if let Ok(mut j) = j.lock() {
                j.record_edge_bypass(edge_ip, physical_gateway, physical_if_idx);
                // Write-ahead (S-6): flush to disk BEFORE the route below is
                // actually added. Previously the journal was only flushed once,
                // after every route had already been installed, so a crash at
                // any point during this function left the just-added routes
                // with nothing on disk to recover them.
                let _ = j.flush_to_disk();
            }
            Some(j)
        } else {
            None
        };

        // 1. Direct host route for VPN Edge server via physical gateway to prevent loops (R-6)
        let edge_route = RouteDefinition {
            destination: edge_ip,
            prefix_len: 32,
            gateway: physical_gateway,
            metric: 1,
        };
        if let Err(e) = backend.add_route(&edge_route, physical_if_idx) {
            if let Some(j) = &journal {
                if let Ok(mut j) = j.lock() {
                    j.clear_routes_and_bypass();
                }
            }
            return Err(e);
        }

        // 2. Split default routes via Wintun adapter (0.0.0.0/1 and 128.0.0.0/1)
        let mut installed = Vec::new();
        let routes = split_tunnel_routes(wintun_ip);

        for route in routes {
            match backend.add_route(&route, wintun_if_idx) {
                Ok(()) => {
                    if let Some(ref j) = journal {
                        if let Ok(mut j) = j.lock() {
                            j.record_route(route.clone(), wintun_if_idx);
                            // Write-ahead per route (S-6): flush immediately so
                            // a crash right after this add still leaves a
                            // journal on disk that knows about it.
                            let _ = j.flush_to_disk();
                        }
                    }
                    installed.push(route);
                }
                Err(err) => {
                    // Atomic Rollback: any failure rolls back all installed routes and edge bypass (R-6)
                    for r in &installed {
                        let _ = backend.delete_route(r, wintun_if_idx);
                    }
                    let _ = backend.delete_route(&edge_route, physical_if_idx);
                    if let Some(j) = &journal {
                        if let Ok(mut j) = j.lock() {
                            j.clear_routes_and_bypass();
                        }
                    }
                    return Err(err);
                }
            }
        }

        if let Some(ref j) = journal {
            if let Ok(j) = j.lock() {
                let _ = j.flush_to_disk();
            }
        }

        Ok(RouteGuard::new(
            installed,
            Some(edge_route),
            physical_if_idx,
            wintun_if_idx,
            backend,
            journal,
        ))
    }
}
