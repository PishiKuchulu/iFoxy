use crate::vpn::network_backend::NetworkBackend;
use crate::vpn::registry::ProxySettingsBackup;
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
}

pub struct RecoveryJournal {
    path: PathBuf,
    state: JournalState,
}

impl RecoveryJournal {
    pub fn default_path() -> PathBuf {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(appdata)
            .join("iFoxy")
            .join("recovery_journal.json")
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
        };
        Self { path, state }
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

    /// Commit the current journal state atomically to disk before network mutation (H5)
    pub fn flush_to_disk(&self) -> Result<(), JournalError> {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let json = serde_json::to_string_pretty(&self.state)?;
        let temp_path = self.path.with_extension("tmp");
        fs::write(&temp_path, json.as_bytes())?;
        fs::rename(&temp_path, &self.path)?;
        Ok(())
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

        // 4. Revert any persistent WFP kill-switch filters (R-8, R-9)
        if !state.wfp_filters.is_empty() {
            tracing::info!(
                "Replaying WFP killswitch filter cleanup for {} filters",
                state.wfp_filters.len()
            );
            let fw = crate::vpn::killswitch::WindowsFirewallBackend::new();
            use crate::vpn::killswitch::FirewallBackend;
            let _ = fw.remove_kill_switch(&state.wfp_filters);
        }

        // 5. Remove dirty journal file
        let _ = fs::remove_file(path);
        tracing::info!("Crash recovery completed successfully. Journal removed.");

        Ok(true)
    }
}
