use crate::vpn::network_backend::{NetworkBackend, WindowsNativeBackend};
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
    let backend = WindowsNativeBackend::new();
    backend.detect_default_gateway_and_interface()
}

pub fn is_admin() -> bool {
    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
    }

    unsafe { IsUserAnAdmin() != 0 }
}

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

pub struct RouteGuard {
    backend: Arc<dyn NetworkBackend>,
    installed_routes: Vec<RouteDefinition>,
    edge_bypass_route: Option<RouteDefinition>,
    physical_if_idx: u32,
    wintun_if_idx: u32,
    journal: Option<RecoveryJournal>,
}

impl RouteGuard {
    pub fn new(
        installed_routes: Vec<RouteDefinition>,
        edge_bypass_route: Option<RouteDefinition>,
        physical_if_idx: u32,
        wintun_if_idx: u32,
        backend: Arc<dyn NetworkBackend>,
        journal: Option<RecoveryJournal>,
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

            if let Some(ref mut j) = self.journal {
                j.record_edge_bypass(edge_route.destination, new_physical_gw, new_physical_if_idx);
                let _ = j.flush_to_disk();
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
            journal.mark_clean();
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
        let backend = Arc::new(WindowsNativeBackend::new());
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
        let mut journal = if use_journal {
            let mut j = RecoveryJournal::new(RecoveryJournal::default_path());
            j.record_edge_bypass(edge_ip, physical_gateway, physical_if_idx);
            // Write-ahead (S-6): flush to disk BEFORE the route below is
            // actually added. Previously the journal was only flushed once,
            // after every route had already been installed, so a crash at
            // any point during this function left the just-added routes
            // with nothing on disk to recover them.
            let _ = j.flush_to_disk();
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
            if let Some(j) = journal {
                j.mark_clean();
            }
            return Err(e);
        }

        // 2. Split default routes via Wintun adapter (0.0.0.0/1 and 128.0.0.0/1)
        let mut installed = Vec::new();
        let routes = split_tunnel_routes(wintun_ip);

        for route in routes {
            match backend.add_route(&route, wintun_if_idx) {
                Ok(()) => {
                    if let Some(ref mut j) = journal {
                        j.record_route(route.clone(), wintun_if_idx);
                        // Write-ahead per route (S-6): flush immediately so
                        // a crash right after this add still leaves a
                        // journal on disk that knows about it.
                        let _ = j.flush_to_disk();
                    }
                    installed.push(route);
                }
                Err(err) => {
                    // Atomic Rollback: any failure rolls back all installed routes and edge bypass (R-6)
                    for r in &installed {
                        let _ = backend.delete_route(r, wintun_if_idx);
                    }
                    let _ = backend.delete_route(&edge_route, physical_if_idx);
                    if let Some(j) = journal {
                        j.mark_clean();
                    }
                    return Err(err);
                }
            }
        }

        if let Some(ref j) = journal {
            let _ = j.flush_to_disk();
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
