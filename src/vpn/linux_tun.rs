//! Linux TUN device: the counterpart of the Windows Wintun adapter.
//!
//! Creates a `/dev/net/tun` interface (IFF_TUN | IFF_NO_PI), assigns the
//! VPN address, MTU and link state with `iproute2`, and points the system
//! resolver at the tunnel DNS (1.1.1.1) for the lifetime of the device —
//! via `resolvectl` per-link DNS when systemd-resolved is managing the
//! system (the setting dies with the link), otherwise by backing up and
//! rewriting `/etc/resolv.conf` (restored on drop). Requires root
//! (CAP_NET_ADMIN), same as the Windows build requires Administrator.

use crate::vpn::packet_pump::TunDeviceOps;
use crate::vpn::routing::detect_default_gateway;
use crate::vpn::wintun_adapter::{resolve_vpn_ip_avoiding_conflict, VPN_ADAPTER_MTU};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use thiserror::Error;

pub const LINUX_TUN_NAME: &str = "ifoxy0";
const TUN_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFNAMSIZ: usize = 16;

#[derive(Error, Debug)]
pub enum TunError {
    #[error("TUN driver error: {0}")]
    Driver(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration command failed: {0}")]
    ConfigFailed(String),
}

#[repr(C)]
struct Ifreq {
    name: [u8; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

fn run_cmd(program: &str, args: &[&str]) -> Result<String, TunError> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| TunError::ConfigFailed(format!("failed to run {}: {}", program, e)))?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(TunError::ConfigFailed(format!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            if stderr.is_empty() { stdout } else { stderr }
        )))
    }
}

fn if_index_of(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}

/// How the tunnel DNS was applied, so it can be undone on drop.
enum DnsGuard {
    /// systemd-resolved per-link DNS: revoked explicitly, and also
    /// disappears with the interface.
    Resolvectl { if_index: u32 },
    /// /etc/resolv.conf was rewritten; holds the original contents.
    ResolvConf { original: String },
    None,
}

pub struct LinuxTunDevice {
    file: File,
    pub name: String,
    pub adapter_index: u32,
    pub ip: Ipv4Addr,
    dns_guard: DnsGuard,
    /// Reused receive buffer (see receive_blocking).
    recv_buf: std::sync::Mutex<Vec<u8>>,
}

impl LinuxTunDevice {
    pub fn create_or_open(preferred_ip: Ipv4Addr) -> Result<Self, TunError> {
        let detected_gw = detect_default_gateway().ok();
        let assigned_ip = resolve_vpn_ip_avoiding_conflict(preferred_ip, detected_gw);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| {
                TunError::Driver(format!(
                    "cannot open /dev/net/tun: {} (root/CAP_NET_ADMIN required)",
                    e
                ))
            })?;

        let mut ifreq = Ifreq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        let name_bytes = LINUX_TUN_NAME.as_bytes();
        ifreq.name[..name_bytes.len()].copy_from_slice(name_bytes);
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifreq) };
        if rc < 0 {
            return Err(TunError::Driver(format!(
                "TUNSETIFF failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let actual_name = {
            let end = ifreq
                .name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(IFNAMSIZ);
            String::from_utf8_lossy(&ifreq.name[..end]).into_owned()
        };

        // Address + MTU + link up (addr add tolerates an existing address
        // from a crashed previous run attaching to the same interface).
        let addr = format!("{}/24", assigned_ip);
        if let Err(e) = run_cmd("ip", &["addr", "add", &addr, "dev", &actual_name]) {
            let msg = format!("{}", e);
            if !msg.contains("File exists") {
                return Err(e);
            }
        }
        run_cmd(
            "ip",
            &[
                "link",
                "set",
                "dev",
                &actual_name,
                "mtu",
                &VPN_ADAPTER_MTU.to_string(),
                "up",
            ],
        )?;

        let adapter_index = if_index_of(&actual_name).ok_or_else(|| {
            TunError::Driver(format!("could not resolve ifindex of {}", actual_name))
        })?;

        let dns_guard = Self::apply_dns(adapter_index);

        tracing::info!(
            "Linux TUN device {} up: ip {} ifindex {} mtu {}",
            actual_name,
            assigned_ip,
            adapter_index,
            VPN_ADAPTER_MTU
        );

        Ok(Self {
            file,
            name: actual_name,
            adapter_index,
            ip: assigned_ip,
            dns_guard,
            recv_buf: std::sync::Mutex::new(vec![0u8; 65536]),
        })
    }

    fn apply_dns(if_index: u32) -> DnsGuard {
        // Preferred: per-link DNS through systemd-resolved. `resolvectl`
        // fails cleanly when resolved is not in charge.
        let idx = if_index.to_string();
        if run_cmd("resolvectl", &["dns", &idx, &TUN_DNS.to_string()]).is_ok() {
            let _ = run_cmd("resolvectl", &["domain", &idx, "~."]);
            return DnsGuard::Resolvectl { if_index };
        }

        // Fallback: rewrite /etc/resolv.conf, keeping the original for
        // restore. Only the nameserver lines are replaced; options and
        // search domains are preserved.
        match std::fs::read_to_string("/etc/resolv.conf") {
            Ok(original) => {
                let mut new_content = format!("nameserver {}\n", TUN_DNS);
                for line in original.lines() {
                    if !line.trim_start().starts_with("nameserver") {
                        new_content.push_str(line);
                        new_content.push('\n');
                    }
                }
                match std::fs::write("/etc/resolv.conf", new_content) {
                    Ok(()) => {
                        // Journal the original for crash recovery: if
                        // the process dies before Drop runs, the next
                        // startup restores it from the journal instead
                        // of leaving DNS pointed at a dead interface
                        // (external review, M1).
                        let journal =
                            crate::vpn::recovery_journal::RecoveryJournal::shared_default();
                        let mut j = journal.lock().unwrap_or_else(|p| p.into_inner());
                        j.record_resolv_conf_backup(original.clone());
                        let _ = j.flush_to_disk();
                        DnsGuard::ResolvConf { original }
                    }
                    Err(e) => {
                        tracing::warn!("could not rewrite /etc/resolv.conf: {}", e);
                        DnsGuard::None
                    }
                }
            }
            Err(e) => {
                tracing::warn!("could not read /etc/resolv.conf: {}", e);
                DnsGuard::None
            }
        }
    }
}

impl Drop for LinuxTunDevice {
    fn drop(&mut self) {
        match &self.dns_guard {
            DnsGuard::Resolvectl { if_index } => {
                let _ = run_cmd("resolvectl", &["revert", &if_index.to_string()]);
            }
            DnsGuard::ResolvConf { original } => {
                if std::fs::write("/etc/resolv.conf", original).is_ok() {
                    let journal =
                        crate::vpn::recovery_journal::RecoveryJournal::shared_default();
                    let mut j = journal.lock().unwrap_or_else(|p| p.into_inner());
                    j.clear_resolv_conf_backup();
                }
            }
            DnsGuard::None => {}
        }
        // Closing the fd (field drop) removes the interface and its routes.
        tracing::info!("Linux TUN device {} closed", self.name);
    }
}

impl TunDeviceOps for LinuxTunDevice {
    fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    fn adapter_index(&self) -> u32 {
        self.adapter_index
    }

    fn send_packet(&self, packet: &[u8]) {
        let mut file = &self.file;
        if let Err(e) = file.write_all(packet) {
            // Was silently discarded (external review, M1): a failing
            // TUN write means outbound traffic is blackholing, which
            // must at least be visible in the log.
            tracing::warn!("TUN write failed ({} bytes): {}", packet.len(), e);
        }
    }

    fn receive_blocking(&self) -> Result<Vec<u8>, String> {
        let mut file = &self.file;
        // Reuse one buffer instead of zero-filling a fresh 64 KiB Vec
        // per packet (external review, M1); only the received bytes
        // are copied out.
        let mut buf = self
            .recv_buf
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match file.read(&mut buf) {
            Ok(n) => Ok(buf[..n].to_vec()),
            Err(e) => Err(e.to_string()),
        }
    }
}
