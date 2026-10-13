use std::net::Ipv4Addr;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct MibIpForwardRow {
    pub dw_forward_dest: u32,
    pub dw_forward_mask: u32,
    pub dw_forward_policy: u32,
    pub dw_forward_next_hop: u32,
    pub dw_forward_if_index: u32,
    pub dw_forward_type: u32,
    pub dw_forward_proto: u32,
    pub dw_forward_age: u32,
    pub dw_forward_next_hop_as: u32,
    pub dw_forward_metric1: u32,
    pub dw_forward_metric2: u32,
    pub dw_forward_metric3: u32,
    pub dw_forward_metric4: u32,
    pub dw_forward_metric5: u32,
}

const _: () = assert!(std::mem::size_of::<MibIpForwardRow>() == 56);

#[repr(C)]
#[derive(Debug)]
pub struct DnsInterfaceSettings {
    pub version: u32,
    pub flags: u64,
    pub domain: *mut u16,
    pub name_server: *mut u16,
    pub search_list: *mut u16,
    pub registration_enabled: u32,
    pub register_adapter_name: u32,
    pub enable_llmnr: u32,
    pub query_adapter_name: u32,
    pub profile_name_server: *mut u16,
}

const _: () = assert!(std::mem::size_of::<DnsInterfaceSettings>() == 64);

pub const DNS_INTERFACE_SETTINGS_VERSION1: u32 = 1;
pub const DNS_SETTING_NAMESERVER: u64 = 0x0002;

#[link(name = "iphlpapi")]
extern "system" {
    fn GetBestRoute(dwdestaddr: u32, dwsourceaddr: u32, pbestroute: *mut MibIpForwardRow) -> u32;

    fn CreateIpForwardEntry(proute: *const MibIpForwardRow) -> u32;

    fn DeleteIpForwardEntry(proute: *const MibIpForwardRow) -> u32;

    fn SetInterfaceDnsSettings(
        interface: windows_sys::core::GUID,
        settings: *const DnsInterfaceSettings,
    ) -> u32;

    fn GetInterfaceDnsSettings(
        interface: windows_sys::core::GUID,
        settings: *mut DnsInterfaceSettings,
    ) -> u32;

    fn FreeInterfaceDnsSettings(settings: *mut DnsInterfaceSettings);
}

pub const NO_ERROR: u32 = 0;
pub const MIB_IPROUTE_TYPE_INDIRECT: u32 = 4;
pub const MIB_IPPROTO_NETMGMT: u32 = 3;

fn ipv4_to_network_u32(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

fn network_u32_to_ipv4(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n.to_ne_bytes())
}

pub fn native_get_best_route_gateway(target: Ipv4Addr) -> Result<Ipv4Addr, u32> {
    native_get_best_route(target).map(|(gw, _)| gw)
}

pub fn native_get_best_route(target: Ipv4Addr) -> Result<(Ipv4Addr, u32), u32> {
    unsafe {
        let mut row = MibIpForwardRow::default();
        let target_u32 = ipv4_to_network_u32(target);
        let ret = GetBestRoute(target_u32, 0, &mut row);
        if ret == NO_ERROR {
            Ok((
                network_u32_to_ipv4(row.dw_forward_next_hop),
                row.dw_forward_if_index,
            ))
        } else {
            Err(ret)
        }
    }
}

pub fn native_create_ip_forward_entry(
    dest: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
    if_index: u32,
    metric: u32,
) -> Result<(), u32> {
    unsafe {
        let row = MibIpForwardRow {
            dw_forward_dest: ipv4_to_network_u32(dest),
            dw_forward_mask: ipv4_to_network_u32(mask),
            dw_forward_policy: 0,
            dw_forward_next_hop: ipv4_to_network_u32(gateway),
            dw_forward_if_index: if_index,
            dw_forward_type: MIB_IPROUTE_TYPE_INDIRECT,
            dw_forward_proto: MIB_IPPROTO_NETMGMT,
            dw_forward_age: 0,
            dw_forward_next_hop_as: 0,
            dw_forward_metric1: metric,
            dw_forward_metric2: u32::MAX,
            dw_forward_metric3: u32::MAX,
            dw_forward_metric4: u32::MAX,
            dw_forward_metric5: u32::MAX,
        };

        let ret = CreateIpForwardEntry(&row);
        if ret == NO_ERROR {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

pub fn native_delete_ip_forward_entry(
    dest: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
    if_index: u32,
) -> Result<(), u32> {
    unsafe {
        let row = MibIpForwardRow {
            dw_forward_dest: ipv4_to_network_u32(dest),
            dw_forward_mask: ipv4_to_network_u32(mask),
            dw_forward_policy: 0,
            dw_forward_next_hop: ipv4_to_network_u32(gateway),
            dw_forward_if_index: if_index,
            dw_forward_type: MIB_IPROUTE_TYPE_INDIRECT,
            dw_forward_proto: MIB_IPPROTO_NETMGMT,
            dw_forward_age: 0,
            dw_forward_next_hop_as: 0,
            dw_forward_metric1: 1,
            dw_forward_metric2: u32::MAX,
            dw_forward_metric3: u32::MAX,
            dw_forward_metric4: u32::MAX,
            dw_forward_metric5: u32::MAX,
        };

        let ret = DeleteIpForwardEntry(&row);
        if ret == NO_ERROR {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

#[cfg(windows)]
pub fn native_set_interface_metric_and_mtu(
    if_index: u32,
    metric: u32,
    mtu: u32,
) -> Result<(), u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    unsafe {
        // SetIpInterfaceEntry rejects (ERROR_INVALID_PARAMETER, 0x57) a row that
        // was not populated from the live interface, so read the current state
        // first and only change the fields we need.
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.Family = 2; // AF_INET = 2
        row.InterfaceIndex = if_index;
        let ret = GetIpInterfaceEntry(&mut row);
        if ret != NO_ERROR {
            return Err(ret);
        }
        // A manual metric is ignored unless automatic metric is disabled.
        row.UseAutomaticMetric = 0;
        row.Metric = metric;
        row.NlMtu = mtu;
        let ret = SetIpInterfaceEntry(&mut row);
        if ret == NO_ERROR {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

#[cfg(not(windows))]
pub fn native_set_interface_metric_and_mtu(
    _if_index: u32,
    _metric: u32,
    _mtu: u32,
) -> Result<(), u32> {
    Ok(())
}

#[cfg(windows)]
pub fn native_set_interface_ip_address(
    if_index: u32,
    ip: Ipv4Addr,
    prefix_len: u8,
) -> Result<(), u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.Address.Ipv4.sin_family = 2; // AF_INET
        row.Address.Ipv4.sin_addr.S_un.S_addr = ipv4_to_network_u32(ip);
        row.InterfaceIndex = if_index;
        row.OnLinkPrefixLength = prefix_len;
        let ret = CreateUnicastIpAddressEntry(&row);
        if ret == NO_ERROR || ret == 5010 {
            // ERROR_OBJECT_ALREADY_EXISTS = 5010
            Ok(())
        } else {
            Err(ret)
        }
    }
}

#[cfg(not(windows))]
pub fn native_set_interface_ip_address(
    _if_index: u32,
    _ip: Ipv4Addr,
    _prefix_len: u8,
) -> Result<(), u32> {
    Ok(())
}

#[cfg(windows)]
pub fn get_interface_guid(if_index: u32) -> Result<windows_sys::core::GUID, u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    unsafe {
        let mut luid: NET_LUID_LH = std::mem::zeroed();
        let ret = ConvertInterfaceIndexToLuid(if_index, &mut luid);
        if ret != 0 {
            return Err(ret);
        }
        let mut guid: windows_sys::core::GUID = std::mem::zeroed();
        let ret = ConvertInterfaceLuidToGuid(&luid, &mut guid);
        if ret != 0 {
            return Err(ret);
        }
        Ok(guid)
    }
}

/// Sets the DNS servers of an interface through `SetInterfaceDnsSettings`.
///
/// `servers` is a comma-separated list of addresses. `None` clears the
/// static list so the interface falls back to automatic (DHCP) DNS; this
/// relies on the documented behavior that a NULL `NameServer` together with
/// the `DNS_SETTING_NAMESERVER` flag resets the setting (not verified here,
/// check with `Get-DnsClientServerAddress` after calling it).
#[cfg(windows)]
pub fn native_set_interface_dns_servers(if_index: u32, servers: Option<&str>) -> Result<(), u32> {
    let guid = get_interface_guid(if_index)?;
    let mut wide: Vec<u16> = match servers {
        Some(list) => list.encode_utf16().chain(std::iter::once(0)).collect(),
        None => Vec::new(),
    };
    let settings = DnsInterfaceSettings {
        version: DNS_INTERFACE_SETTINGS_VERSION1,
        flags: DNS_SETTING_NAMESERVER,
        domain: std::ptr::null_mut(),
        name_server: if servers.is_some() {
            wide.as_mut_ptr()
        } else {
            std::ptr::null_mut()
        },
        search_list: std::ptr::null_mut(),
        registration_enabled: 0,
        register_adapter_name: 0,
        enable_llmnr: 0,
        query_adapter_name: 0,
        profile_name_server: std::ptr::null_mut(),
    };
    // SAFETY: `settings` and the wide-string buffer it points to outlive the
    // call; the API only reads them.
    let ret = unsafe { SetInterfaceDnsSettings(guid, &settings) };
    if ret == NO_ERROR {
        Ok(())
    } else {
        Err(ret)
    }
}

#[cfg(windows)]
pub fn native_set_interface_dns(if_index: u32, dns_server: Ipv4Addr) -> Result<(), u32> {
    native_set_interface_dns_servers(if_index, Some(&dns_server.to_string()))
}

/// Not supported off Windows. Returning an error (instead of the previous
/// non-operational `Ok(())`) means a caller can never mistake "did nothing" for success.
#[cfg(not(windows))]
pub fn native_set_interface_dns_servers(_if_index: u32, _servers: Option<&str>) -> Result<(), u32> {
    Err(1)
}

#[cfg(not(windows))]
pub fn native_set_interface_dns(_if_index: u32, _dns_server: Ipv4Addr) -> Result<(), u32> {
    Err(1)
}

#[cfg(windows)]
pub fn native_get_interface_dns(if_index: u32) -> Result<Option<String>, u32> {
    let guid = get_interface_guid(if_index)?;
    unsafe {
        let mut settings: DnsInterfaceSettings = std::mem::zeroed();
        settings.version = DNS_INTERFACE_SETTINGS_VERSION1;
        let ret = GetInterfaceDnsSettings(guid, &mut settings);
        if ret != NO_ERROR {
            return Err(ret);
        }
        let res = if !settings.name_server.is_null() {
            let mut len = 0;
            while *settings.name_server.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(settings.name_server, len);
            Some(String::from_utf16_lossy(slice))
        } else {
            None
        };
        FreeInterfaceDnsSettings(&mut settings);
        Ok(res)
    }
}

#[cfg(not(windows))]
pub fn native_get_interface_dns(_if_index: u32) -> Result<Option<String>, u32> {
    Err(1)
}

pub fn native_set_adapter_dns(adapter_guid: &str, dns_server: Ipv4Addr) -> Result<(), String> {
    let subkey = format!(
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{{{}}}",
        adapter_guid
    );
    crate::vpn::registry::WinRegistry::write_hklm_string(
        &subkey,
        "NameServer",
        &dns_server.to_string(),
    )
}

#[cfg(windows)]
pub struct RouteChangeSubscription {
    handle: windows_sys::Win32::Foundation::HANDLE,
    _ctx: Box<tokio::sync::mpsc::Sender<()>>,
}

#[cfg(windows)]
unsafe impl Send for RouteChangeSubscription {}
#[cfg(windows)]
unsafe impl Sync for RouteChangeSubscription {}

#[cfg(windows)]
impl Drop for RouteChangeSubscription {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe {
                let _ = windows_sys::Win32::NetworkManagement::IpHelper::CancelMibChangeNotify2(
                    self.handle,
                );
            }
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn route_change_callback(
    caller_context: *const std::ffi::c_void,
    _row: *const windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2,
    _notification_type: windows_sys::Win32::NetworkManagement::IpHelper::MIB_NOTIFICATION_TYPE,
) {
    if !caller_context.is_null() {
        let sender = &*(caller_context as *const tokio::sync::mpsc::Sender<()>);
        let _ = sender.try_send(());
    }
}

#[cfg(windows)]
pub fn subscribe_route_changes(
    sender: tokio::sync::mpsc::Sender<()>,
) -> Result<RouteChangeSubscription, u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::NotifyRouteChange2;
    let mut handle: windows_sys::Win32::Foundation::HANDLE = 0 as _;
    let ctx = Box::new(sender);
    let ctx_ptr = &*ctx as *const tokio::sync::mpsc::Sender<()> as *const std::ffi::c_void;
    const AF_INET: u16 = 2; // AF_INET

    let ret = unsafe {
        NotifyRouteChange2(
            AF_INET,
            Some(route_change_callback),
            ctx_ptr,
            0, // false for initial notification
            &mut handle,
        )
    };

    if ret == NO_ERROR {
        Ok(RouteChangeSubscription { handle, _ctx: ctx })
    } else {
        Err(ret)
    }
}

#[cfg(not(windows))]
pub struct RouteChangeSubscription;

#[cfg(not(windows))]
pub fn subscribe_route_changes(
    _sender: tokio::sync::mpsc::Sender<()>,
) -> Result<RouteChangeSubscription, u32> {
    Err(1)
}
