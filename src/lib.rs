pub const APP_NAME: &str = "iFoxy";
/// Single source of truth for the version string: Cargo.toml
/// (wave-3 review, M-1 — a hand-maintained copy had gone stale).
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod auth;
pub mod control_api;
pub mod crypto;
pub mod guardian;
pub mod http_client;
pub mod logging;
pub mod paths;
pub mod security;
pub mod servers;
pub mod syscmd;
pub mod service;
pub mod tauri_bridge;
pub mod tunnel;
pub mod vpn;
