//! Absolute-path resolution for external system tools (wave-3 review,
//! C-3).
//!
//! The desktop process runs ELEVATED, and it used to spawn every helper
//! (`iptables`, `ip`, `netsh`, `resolvectl`, `gsettings`, `pkexec`, …)
//! by bare name. Name lookup follows the process PATH — which, in an
//! elevated process whose environment is inherited from the user's
//! session, an attacker-writable directory could poison to run
//! arbitrary code as root/Administrator. Tools are now resolved to a
//! fixed system directory whenever one contains them; the bare name is
//! only a last-resort fallback for exotic layouts (e.g. NixOS), so
//! functionality never hard-breaks on an unusual system.

use std::path::PathBuf;

/// Resolve a system tool to an absolute path when it exists in a
/// well-known system directory; otherwise return the bare name.
pub fn tool_path(name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(system_root) = std::env::var("SystemRoot") {
            let candidate = PathBuf::from(system_root)
                .join("System32")
                .join(format!("{name}.exe"));
            if candidate.exists() {
                return candidate;
            }
        }
        PathBuf::from(name)
    }
    #[cfg(not(windows))]
    {
        const SYSTEM_DIRS: [&str; 6] = [
            "/usr/sbin",
            "/sbin",
            "/usr/bin",
            "/bin",
            "/usr/local/sbin",
            "/usr/local/bin",
        ];
        for dir in SYSTEM_DIRS {
            let candidate = PathBuf::from(dir).join(name);
            if candidate.exists() {
                return candidate;
            }
        }
        PathBuf::from(name)
    }
}
