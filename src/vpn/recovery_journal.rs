use crate::vpn::network_backend::NetworkBackend;
use crate::vpn::system_proxy::ProxySettingsBackup;
use crate::vpn::routing::RouteDefinition;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JournalError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalRouteEntry {
    pub route: RouteDefinition,
    pub if_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EdgeBypassEntry {
    pub edge_ip: Ipv4Addr,
    pub physical_gw: Ipv4Addr,
    pub physical_if_idx: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalState {
    pub pid: u32,
    pub timestamp_epoch: u64,
    pub installed_routes: Vec<JournalRouteEntry>,
    pub edge_bypass: Option<EdgeBypassEntry>,
    pub proxy_backup: Option<ProxySettingsBackup>,
    pub wfp_filters: Vec<u64>,
    /// Original /etc/resolv.conf contents when the Linux TUN fallback
    /// rewrote it (crash recovery restores it). `serde(default)` keeps
    /// journals written by older builds readable.
    #[serde(default)]
    pub resolv_conf_backup: Option<String>,
}

impl JournalState {
    fn is_empty(&self) -> bool {
        self.installed_routes.is_empty()
            && self.edge_bypass.is_none()
            && self.proxy_backup.is_none()
            && self.wfp_filters.is_empty()
            && self.resolv_conf_backup.is_none()
    }
}

pub struct RecoveryJournal {
    path: PathBuf,
    state: JournalState,
}

impl RecoveryJournal {
    pub fn default_path() -> PathBuf {
        crate::paths::config_dir().join("recovery_journal.json")
    }

    pub fn new(path: PathBuf) -> Self {
        let state = JournalState {
            pid: std::process::id(),
            timestamp_epoch: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            installed_routes: Vec::new(),
            edge_bypass: None,
            proxy_backup: None,
            wfp_filters: Vec::new(),
            resolv_conf_backup: None,
        };
        Self { path, state }
    }

    /// The one journal instance every production subsystem shares.
    ///
    /// RouteManager, SystemProxyGuard and KillSwitchGuard each used to
    /// construct their OWN RecoveryJournal over the same file, so the
    /// last flush overwrote the other subsystems' records and one
    /// guard's clean shutdown deleted records the others still needed
    /// (external review, S6). All production users now record into this
    /// shared instance and clear only their own section.
    pub fn shared_default() -> std::sync::Arc<std::sync::Mutex<RecoveryJournal>> {
        static SHARED: std::sync::OnceLock<
            std::sync::Arc<std::sync::Mutex<RecoveryJournal>>,
        > = std::sync::OnceLock::new();
        SHARED
            .get_or_init(|| {
                std::sync::Arc::new(std::sync::Mutex::new(RecoveryJournal::new(
                    RecoveryJournal::default_path(),
                )))
            })
            .clone()
    }

    pub fn record_route(&mut self, route: RouteDefinition, if_index: u32) {
        self.state
            .installed_routes
            .push(JournalRouteEntry { route, if_index });
    }

    pub fn record_edge_bypass(
        &mut self,
        edge_ip: Ipv4Addr,
        physical_gw: Ipv4Addr,
        physical_if_idx: u32,
    ) {
        self.state.edge_bypass = Some(EdgeBypassEntry {
            edge_ip,
            physical_gw,
            physical_if_idx,
        });
    }

    pub fn record_proxy_backup(&mut self, backup: ProxySettingsBackup) {
        self.state.proxy_backup = Some(backup);
    }

    pub fn record_wfp_filter(&mut self, filter_id: u64) {
        self.state.wfp_filters.push(filter_id);
    }

    pub fn record_resolv_conf_backup(&mut self, original_contents: String) {
        self.state.resolv_conf_backup = Some(original_contents);
    }

    /// Commit the current journal state atomically to disk before network mutation (H5)
    pub fn flush_to_disk(&self) -> Result<(), JournalError> {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let json = serde_json::to_string_pretty(&self.state)?;
        let temp_path = self.path.with_extension("tmp");
        fs::write(&temp_path, json.as_bytes())?;
        // fsync before the rename: the write-ahead guarantee the docs
        // claim ("flushed to disk prior to executing the system API
        // call") is only real if the bytes survive a power loss, not
        // just a process crash (external review, S6c).
        {
            let tmp = fs::File::open(&temp_path)?;
            tmp.sync_all()?;
        }
        fs::rename(&temp_path, &self.path)?;
        if let Some(parent) = self.path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Section-scoped cleanup for the shared journal: each subsystem
    /// clears only the records it owns. The journal file is removed
    /// once no section has anything left to recover.
    fn clear_section(&mut self, clear: impl FnOnce(&mut JournalState)) {
        clear(&mut self.state);
        if self.state.is_empty() {
            self.mark_clean();
        } else {
            let _ = self.flush_to_disk();
        }
    }

    pub fn clear_routes_and_bypass(&mut self) {
        self.clear_section(|s| {
            s.installed_routes.clear();
            s.edge_bypass = None;
        });
    }

    pub fn clear_proxy_backup(&mut self) {
        self.clear_section(|s| {
            s.proxy_backup = None;
        });
    }

    /// Remove only the filter ids one guard recorded (multiset
    /// subtraction: one occurrence per id). Two guards can hold
    /// records in the shared journal at once — e.g. a carried-forward
    /// kill switch and its replacement during a reconnect handoff —
    /// and one guard's cleanup must not erase the other's records.
    pub fn clear_wfp_filters_for(&mut self, ids: &[u64]) {
        let mut to_remove: Vec<u64> = ids.to_vec();
        self.clear_section(|s| {
            s.wfp_filters.retain(|fid| {
                if let Some(pos) = to_remove.iter().position(|x| x == fid) {
                    to_remove.remove(pos);
                    false
                } else {
                    true
                }
            });
        });
    }

    pub fn clear_resolv_conf_backup(&mut self) {
        self.clear_section(|s| {
            s.resolv_conf_backup = None;
        });
    }

    /// Mark clean shutdown by deleting the journal file from disk
    pub fn mark_clean(&self) {
        if self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
    }

    /// Startup crash recovery: if a journal file exists, replay cleanup and remove file (H5)
    pub fn recover_if_dirty(
        path: &Path,
        backend: &dyn NetworkBackend,
    ) -> Result<bool, JournalError> {
        if !path.exists() {
            return Ok(false);
        }

        tracing::warn!(
            "Dirty recovery journal detected at {:?}! Rolling back crashed network state...",
            path
        );

        let data = fs::read(path)?;
        let state: JournalState = serde_json::from_slice(&data)?;

        // 1. Revert all installed VPN routes
        for entry in &state.installed_routes {
            tracing::info!(
                "Replaying route cleanup for destination {}/{}",
                entry.route.destination,
                entry.route.prefix_len
            );
            let _ = backend.delete_route(&entry.route, entry.if_index);
        }

        // 2. Revert edge bypass route using physical_if_idx
        if let Some(ref entry) = state.edge_bypass {
            let edge_route = RouteDefinition {
                destination: entry.edge_ip,
                prefix_len: 32,
                gateway: entry.physical_gw,
                metric: 1,
            };
            let _ = backend.delete_route(&edge_route, entry.physical_if_idx);
        }

        // 3. Revert system proxy settings
        if let Some(ref backup) = state.proxy_backup {
            tracing::info!("Replaying proxy restore from journal backup");
            let _ = backend.restore_system_proxy(Some(backup));
        }

        // 4. Revert any persistent kill-switch state (R-8, R-9): WFP
        // filters on Windows (normally reaped with the dynamic session,
        // but a journal entry means a previous run asked for removal),
        // the iptables chains on Linux (which genuinely persist).
        if !state.wfp_filters.is_empty() {
            tracing::info!(
                "Replaying killswitch cleanup for {} recorded rules",
                state.wfp_filters.len()
            );
            let fw = crate::vpn::killswitch::platform_firewall_backend();
            let _ = fw.remove_kill_switch(&state.wfp_filters);
        }

        // 5. Restore a rewritten /etc/resolv.conf (Linux TUN DNS
        // fallback): a crash between the rewrite and the device Drop
        // otherwise leaves DNS pointing at a dead interface forever.
        if let Some(ref original) = state.resolv_conf_backup {
            tracing::info!("Replaying resolv.conf restore from journal backup");
            if let Err(e) = fs::write("/etc/resolv.conf", original) {
                tracing::warn!("Failed to restore /etc/resolv.conf from journal: {}", e);
            }
        }

        // 6. Remove dirty journal file
        let _ = fs::remove_file(path);
        tracing::info!("Crash recovery completed successfully. Journal removed.");

        Ok(true)
    }
}
