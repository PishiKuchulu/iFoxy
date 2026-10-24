//! System-proxy store: the per-OS mechanism behind ProxyOnly mode.
//!
//! Windows uses the per-user Internet Settings registry keys (unchanged
//! from the original implementation). Linux uses GNOME's
//! `org.gnome.system.proxy` via `gsettings` — written as the *desktop
//! user*, not as root: iFoxy runs elevated, and a root-owned dconf
//! database would never reach the user's session, so when the app was
//! started through pkexec the gsettings calls are re-executed as the
//! invoking user (PKEXEC_UID) with their session bus.

use crate::vpn::recovery_journal::RecoveryJournal;
use std::sync::Arc;
#[cfg(windows)]
use crate::vpn::registry::WinRegistry;
#[cfg(windows)]
pub use crate::vpn::registry::ProxySettingsBackup;

#[cfg(target_os = "linux")]
use serde::{Deserialize, Serialize};

/// Snapshot of the pre-iFoxy system proxy settings (Linux form: the raw
/// `gsettings get` output for every key [apply_system_proxy] touches,
/// replayed verbatim on restore).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySettingsBackup {
    pub entries: Vec<(String, String, String)>,
}

// ---------------------------------------------------------------------------
// Windows store
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[link(name = "wininet")]
extern "system" {
    fn InternetSetOptionW(
        hinternet: *mut std::ffi::c_void,
        dwoption: u32,
        lpbuffer: *mut std::ffi::c_void,
        dwbufferlength: u32,
    ) -> i32;
}

#[cfg(windows)]
pub fn notify_system_settings_changed() {
    unsafe {
        // 39 = INTERNET_OPTION_SETTINGS_CHANGED
        InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0);
        // 37 = INTERNET_OPTION_REFRESH
        InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0);
    }
}

#[cfg(windows)]
pub fn backup_proxy_settings() -> ProxySettingsBackup {
    WinRegistry::backup_proxy_settings()
}

#[cfg(windows)]
pub fn apply_system_proxy(port: u16) -> Result<(), String> {
    // https= and socks= only: plain http:// is rejected by the local proxy
    // (501), so it must not be advertised (S-9).
    let proxy_server = format!("https=127.0.0.1:{port};socks=127.0.0.1:{port}");
    WinRegistry::write_internet_dword("ProxyEnable", 1)?;
    WinRegistry::write_internet_string("ProxyServer", &proxy_server)?;
    notify_system_settings_changed();
    Ok(())
}

#[cfg(windows)]
pub fn restore_system_proxy(backup: Option<&ProxySettingsBackup>) -> Result<(), String> {
    if let Some(b) = backup {
        WinRegistry::restore_proxy_settings(b)?;
    } else {
        WinRegistry::write_internet_dword("ProxyEnable", 0)?;
    }
    notify_system_settings_changed();
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux store (GNOME gsettings)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const PROXY_SCHEMA: &str = "org.gnome.system.proxy";

#[cfg(target_os = "linux")]
const PROXY_KEYS: &[(&str, &str)] = &[
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy", "autoconfig-url"),
    ("org.gnome.system.proxy", "ignore-hosts"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.http", "enabled"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    ("org.gnome.system.proxy.socks", "host"),
    ("org.gnome.system.proxy.socks", "port"),
];

/// Run `gsettings` as the desktop user (see the module docs): when the
/// process is root via pkexec/sudo, wrap with runuser and the user's
/// session-bus environment; otherwise run directly.
#[cfg(target_os = "linux")]
fn gsettings(args: &[&str]) -> Result<String, String> {
    let desktop_uid = std::env::var("PKEXEC_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|&uid| uid != 0);
    let am_root = unsafe { libc::geteuid() } == 0;

    let out = if let (true, Some(uid)) = (am_root, desktop_uid) {
        let runtime_dir = format!("/run/user/{}", uid);
        let bus = format!("unix:path={}/bus", runtime_dir);
        let mut cmd = std::process::Command::new("runuser");
        cmd.args(["-u", &uid.to_string(), "--", "env"])
            .arg(format!("XDG_RUNTIME_DIR={}", runtime_dir))
            .arg(format!("DBUS_SESSION_BUS_ADDRESS={}", bus))
            .arg("gsettings")
            .args(args);
        cmd.output()
    } else {
        std::process::Command::new("gsettings").args(args).output()
    }
    .map_err(|e| format!("failed to run gsettings (is gsettings installed?): {}", e))?;

    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!(
            "gsettings {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(target_os = "linux")]
pub fn backup_proxy_settings() -> ProxySettingsBackup {
    let mut entries = Vec::new();
    for (schema, key) in PROXY_KEYS {
        if let Ok(value) = gsettings(&["get", schema, key]) {
            entries.push((schema.to_string(), key.to_string(), value));
        }
    }
    ProxySettingsBackup { entries }
}

#[cfg(target_os = "linux")]
pub fn apply_system_proxy(port: u16) -> Result<(), String> {
    let port_s = port.to_string();
    // Mirror the Windows advertisement: https + socks only (S-9).
    gsettings(&["set", "org.gnome.system.proxy.https", "host", "127.0.0.1"])?;
    gsettings(&["set", "org.gnome.system.proxy.https", "port", &port_s])?;
    gsettings(&["set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"])?;
    gsettings(&["set", "org.gnome.system.proxy.socks", "port", &port_s])?;
    gsettings(&["set", "org.gnome.system.proxy.http", "enabled", "false"])?;
    gsettings(&["set", PROXY_SCHEMA, "mode", "'manual'"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn restore_system_proxy(backup: Option<&ProxySettingsBackup>) -> Result<(), String> {
    match backup {
        Some(b) => {
            for (schema, key, value) in &b.entries {
                gsettings(&["set", schema, key, value])?;
            }
            Ok(())
        }
        None => gsettings(&["set", PROXY_SCHEMA, "mode", "'none'"]).map(|_| ()),
    }
}

// ---------------------------------------------------------------------------
// Guard (shared): journal write-ahead + apply/restore on drop
// ---------------------------------------------------------------------------

pub struct SystemProxyGuard {
    active: bool,
    backup: Option<ProxySettingsBackup>,
    journal: Option<Arc<std::sync::Mutex<RecoveryJournal>>>,
}

impl SystemProxyGuard {
    pub fn enable(port: u16) -> Result<Self, String> {
        let backup = backup_proxy_settings();

        // Write-ahead (S-6): persist the ORIGINAL settings to the recovery
        // journal BEFORE overwriting them. Previously the backup lived only
        // in memory, so a crash in proxy-only mode left the system proxy
        // pointing at a dead port with no on-disk record to restore from.
        // The journal is the shared instance, so this record coexists with
        // the route / kill-switch / DNS records instead of overwriting
        // them (external review, S6b).
        let journal = RecoveryJournal::shared_default();
        if let Ok(mut j) = journal.lock() {
            j.record_proxy_backup(backup.clone());
            if let Err(e) = j.flush_to_disk() {
                tracing::warn!("Failed to write proxy recovery journal: {:?}", e);
            }
        }

        apply_system_proxy(port)?;

        tracing::info!("System Proxy enabled pointing to 127.0.0.1:{}", port);
        Ok(Self {
            active: true,
            backup: Some(backup),
            journal: Some(journal),
        })
    }

    pub fn disable(&mut self) {
        if self.active {
            self.active = false;
            match restore_system_proxy(self.backup.as_ref()) {
                Ok(()) => {
                    tracing::info!("System Proxy restored to previous settings");
                    if let Some(ref j) = self.journal {
                        if let Ok(mut j) = j.lock() {
                            j.clear_proxy_backup();
                        }
                    }
                }
                Err(e) => {
                    // Keep the journal record: the next startup's crash
                    // recovery will replay this restore. Marking the
                    // journal clean here (the old behavior) destroyed the
                    // only on-disk copy of the user's original settings
                    // exactly when the restore had failed (external
                    // review, S6d).
                    tracing::error!(
                        "System Proxy restore FAILED: {:?} — original settings kept in the recovery journal for next-startup replay",
                        e
                    );
                }
            }
        }
    }

    pub fn backup(&self) -> Option<&ProxySettingsBackup> {
        self.backup.as_ref()
    }
}

impl Drop for SystemProxyGuard {
    fn drop(&mut self) {
        self.disable();
    }
}
