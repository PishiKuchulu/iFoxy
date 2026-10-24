//! Per-OS locations for iFoxy's per-user files (session secrets, the
//! recovery journal, logs, WebView data).
//!
//! Windows keeps the historical locations (`%APPDATA%\iFoxy` and
//! `%LOCALAPPDATA%\iFoxy`) so existing installs are untouched. Linux
//! follows the XDG base-directory spec.

use std::path::PathBuf;

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var(var).ok().filter(|v| !v.is_empty()).map(PathBuf::from)
}

// Only the XDG (non-Windows) roots fall back to the home directory;
// Windows derives its roots from APPDATA/LOCALAPPDATA directly.
#[cfg(not(windows))]
fn home_dir() -> PathBuf {
    env_path("HOME").unwrap_or_else(|| PathBuf::from("."))
}

/// Configuration + secrets: Windows `%APPDATA%`, Linux `$XDG_CONFIG_HOME`
/// (or `~/.config`).
pub fn config_root() -> PathBuf {
    #[cfg(windows)]
    {
        env_path("APPDATA").unwrap_or_else(|| PathBuf::from("."))
    }
    #[cfg(not(windows))]
    {
        env_path("XDG_CONFIG_HOME").unwrap_or_else(|| home_dir().join(".config"))
    }
}

/// Local app data (WebView profile): Windows `%LOCALAPPDATA%`, Linux
/// `$XDG_DATA_HOME` (or `~/.local/share`).
pub fn data_root() -> PathBuf {
    #[cfg(windows)]
    {
        env_path("LOCALAPPDATA").unwrap_or_else(|| PathBuf::from("."))
    }
    #[cfg(not(windows))]
    {
        env_path("XDG_DATA_HOME").unwrap_or_else(|| home_dir().join(".local").join("share"))
    }
}

/// Logs/state: Windows `%LOCALAPPDATA%`, Linux `$XDG_STATE_HOME`
/// (or `~/.local/state`).
pub fn state_root() -> PathBuf {
    #[cfg(windows)]
    {
        data_root()
    }
    #[cfg(not(windows))]
    {
        env_path("XDG_STATE_HOME").unwrap_or_else(|| home_dir().join(".local").join("state"))
    }
}

pub fn config_dir() -> PathBuf {
    config_root().join("iFoxy")
}

pub fn data_dir() -> PathBuf {
    data_root().join("iFoxy")
}

pub fn state_dir() -> PathBuf {
    state_root().join("iFoxy")
}
