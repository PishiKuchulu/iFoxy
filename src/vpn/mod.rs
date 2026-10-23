pub mod edge_resolver;
#[cfg(windows)]
pub mod iphlpapi;
pub mod killswitch;
#[cfg(target_os = "linux")]
pub mod linux_tun;
pub mod local_proxy;
pub mod netstack;
pub mod network_backend;
pub mod packet;
pub mod packet_pump;
pub mod recovery_journal;
#[cfg(windows)]
pub mod registry;
pub mod routing;
pub mod system_proxy;
pub mod wintun_adapter;
