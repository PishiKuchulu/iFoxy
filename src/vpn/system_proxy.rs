use crate::vpn::recovery_journal::RecoveryJournal;
use crate::vpn::registry::{ProxySettingsBackup, WinRegistry};

#[link(name = "wininet")]
extern "system" {
    fn InternetSetOptionW(
        hinternet: *mut std::ffi::c_void,
        dwoption: u32,
        lpbuffer: *mut std::ffi::c_void,
        dwbufferlength: u32,
    ) -> i32;
}

pub fn notify_system_settings_changed() {
    unsafe {
        // 39 = INTERNET_OPTION_SETTINGS_CHANGED
        InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0);
        // 37 = INTERNET_OPTION_REFRESH
        InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0);
    }
}

pub struct SystemProxyGuard {
    active: bool,
    backup: Option<ProxySettingsBackup>,
    journal: Option<RecoveryJournal>,
}

impl SystemProxyGuard {
    pub fn enable(port: u16) -> Result<Self, String> {
        let backup = WinRegistry::backup_proxy_settings();
        // Advertise only https= (and socks=), not http=: the local proxy
        // (local_proxy.rs) answers a plain HTTP absolute-URI request with
        // 501 Not Implemented rather than forwarding it, so advertising
        // http= here made every plain-HTTP site fail while claiming to
        // support it (S-9 in the round-3 review).
        let proxy_server = format!("https=127.0.0.1:{port};socks=127.0.0.1:{port}");

        // Write-ahead (S-6): persist the ORIGINAL settings to the recovery
        // journal BEFORE overwriting them. Previously the backup lived only
        // in memory, so a crash in proxy-only mode left the system proxy
        // pointing at a dead port with no on-disk record to restore from.
        let mut journal = RecoveryJournal::new(RecoveryJournal::default_path());
        journal.record_proxy_backup(backup.clone());
        if let Err(e) = journal.flush_to_disk() {
            tracing::warn!("Failed to write proxy recovery journal: {:?}", e);
        }

        WinRegistry::write_internet_dword("ProxyEnable", 1)?;
        WinRegistry::write_internet_string("ProxyServer", &proxy_server)?;

        notify_system_settings_changed();
        tracing::info!(
            "Windows System Proxy enabled pointing to 127.0.0.1:{}",
            port
        );
        Ok(Self {
            active: true,
            backup: Some(backup),
            journal: Some(journal),
        })
    }

    pub fn disable(&mut self) {
        if self.active {
            if let Some(ref backup) = self.backup.take() {
                let _ = WinRegistry::restore_proxy_settings(backup);
            } else {
                let _ = WinRegistry::write_internet_dword("ProxyEnable", 0);
            }

            notify_system_settings_changed();
            tracing::info!("Windows System Proxy restored to previous settings");
            self.active = false;
            if let Some(ref j) = self.journal {
                j.mark_clean();
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
