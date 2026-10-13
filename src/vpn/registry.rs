use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(
        hkey: *mut c_void,
        lpsubkey: *const u16,
        uloptions: u32,
        samdesired: u32,
        phkresult: *mut *mut c_void,
    ) -> i32;

    fn RegQueryValueExW(
        hkey: *mut c_void,
        lpvaluename: *const u16,
        lpreserved: *mut u32,
        lptype: *mut u32,
        lpdata: *mut u8,
        lpcbdata: *mut u32,
    ) -> i32;

    fn RegSetValueExW(
        hkey: *mut c_void,
        lpvaluename: *const u16,
        reserved: u32,
        dwtype: u32,
        lpdata: *const u8,
        cbdata: u32,
    ) -> i32;

    fn RegCloseKey(hkey: *mut c_void) -> i32;
}

const HKEY_CURRENT_USER: *mut c_void = 0x80000001usize as *mut c_void;
pub const HKEY_LOCAL_MACHINE: *mut c_void = 0x80000002usize as *mut c_void;
const KEY_READ: u32 = 0x20019;
const KEY_WRITE: u32 = 0x20006;
const REG_DWORD: u32 = 4;
const REG_SZ: u32 = 1;
const ERROR_SUCCESS: i32 = 0;

const INTERNET_SETTINGS_KEY: &str =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxySettingsBackup {
    pub proxy_enable: Option<u32>,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
}

fn to_wide_null(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub struct WinRegistry;

impl WinRegistry {
    /// Read DWORD value from HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    pub fn read_internet_dword(name: &str) -> Option<u32> {
        unsafe {
            let key_wide = to_wide_null(INTERNET_SETTINGS_KEY);
            let mut hkey: *mut c_void = std::ptr::null_mut();
            if RegOpenKeyExW(HKEY_CURRENT_USER, key_wide.as_ptr(), 0, KEY_READ, &mut hkey)
                != ERROR_SUCCESS
            {
                return None;
            }

            let name_wide = to_wide_null(name);
            let mut val_type: u32 = 0;
            let mut data: u32 = 0;
            let mut data_len: u32 = std::mem::size_of::<u32>() as u32;

            let res = RegQueryValueExW(
                hkey,
                name_wide.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                &mut data as *mut u32 as *mut u8,
                &mut data_len,
            );

            RegCloseKey(hkey);

            if res == ERROR_SUCCESS && val_type == REG_DWORD {
                Some(data)
            } else {
                None
            }
        }
    }

    /// Read String (SZ) value from HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    pub fn read_internet_string(name: &str) -> Option<String> {
        unsafe {
            let key_wide = to_wide_null(INTERNET_SETTINGS_KEY);
            let mut hkey: *mut c_void = std::ptr::null_mut();
            if RegOpenKeyExW(HKEY_CURRENT_USER, key_wide.as_ptr(), 0, KEY_READ, &mut hkey)
                != ERROR_SUCCESS
            {
                return None;
            }

            let name_wide = to_wide_null(name);
            let mut val_type: u32 = 0;
            let mut buf_len: u32 = 0;

            // First query buffer length
            if RegQueryValueExW(
                hkey,
                name_wide.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                std::ptr::null_mut(),
                &mut buf_len,
            ) != ERROR_SUCCESS
            {
                RegCloseKey(hkey);
                return None;
            }

            if buf_len == 0 {
                RegCloseKey(hkey);
                return Some(String::new());
            }

            let mut buf: Vec<u8> = vec![0; buf_len as usize];
            let res = RegQueryValueExW(
                hkey,
                name_wide.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                buf.as_mut_ptr(),
                &mut buf_len,
            );

            RegCloseKey(hkey);

            if res == ERROR_SUCCESS && val_type == REG_SZ {
                // Wide string decoding (UTF-16LE)
                let u16_slice: &[u16] =
                    std::slice::from_raw_parts(buf.as_ptr() as *const u16, buf.len() / 2);
                // Trim trailing null characters
                let trimmed = match u16_slice.iter().position(|&c| c == 0) {
                    Some(idx) => &u16_slice[..idx],
                    None => u16_slice,
                };
                Some(String::from_utf16_lossy(trimmed))
            } else {
                None
            }
        }
    }

    /// Write DWORD value to HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    pub fn write_internet_dword(name: &str, value: u32) -> Result<(), String> {
        unsafe {
            let key_wide = to_wide_null(INTERNET_SETTINGS_KEY);
            let mut hkey: *mut c_void = std::ptr::null_mut();
            let res = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                key_wide.as_ptr(),
                0,
                KEY_WRITE,
                &mut hkey,
            );
            if res != ERROR_SUCCESS {
                return Err(format!("RegOpenKeyExW failed with code {}", res));
            }

            let name_wide = to_wide_null(name);
            let set_res = RegSetValueExW(
                hkey,
                name_wide.as_ptr(),
                0,
                REG_DWORD,
                &value as *const u32 as *const u8,
                std::mem::size_of::<u32>() as u32,
            );

            RegCloseKey(hkey);

            if set_res == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(format!("RegSetValueExW failed with code {}", set_res))
            }
        }
    }

    /// Write String (SZ) value to HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    pub fn write_internet_string(name: &str, value: &str) -> Result<(), String> {
        unsafe {
            let key_wide = to_wide_null(INTERNET_SETTINGS_KEY);
            let mut hkey: *mut c_void = std::ptr::null_mut();
            let res = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                key_wide.as_ptr(),
                0,
                KEY_WRITE,
                &mut hkey,
            );
            if res != ERROR_SUCCESS {
                return Err(format!("RegOpenKeyExW failed with code {}", res));
            }

            let name_wide = to_wide_null(name);
            let val_wide = to_wide_null(value);
            let set_res = RegSetValueExW(
                hkey,
                name_wide.as_ptr(),
                0,
                REG_SZ,
                val_wide.as_ptr() as *const u8,
                (val_wide.len() * 2) as u32,
            );

            RegCloseKey(hkey);

            if set_res == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(format!("RegSetValueExW failed with code {}", set_res))
            }
        }
    }

    /// Write String (SZ) value to HKEY_LOCAL_MACHINE\<subkey>
    pub fn write_hklm_string(subkey: &str, name: &str, value: &str) -> Result<(), String> {
        unsafe {
            let key_wide = to_wide_null(subkey);
            let mut hkey: *mut c_void = std::ptr::null_mut();
            let res = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                key_wide.as_ptr(),
                0,
                KEY_WRITE,
                &mut hkey,
            );
            if res != ERROR_SUCCESS {
                return Err(format!("RegOpenKeyExW failed with code {}", res));
            }

            let name_wide = to_wide_null(name);
            let val_wide = to_wide_null(value);
            let set_res = RegSetValueExW(
                hkey,
                name_wide.as_ptr(),
                0,
                REG_SZ,
                val_wide.as_ptr() as *const u8,
                (val_wide.len() * 2) as u32,
            );

            RegCloseKey(hkey);

            if set_res == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(format!("RegSetValueExW failed with code {}", set_res))
            }
        }
    }

    /// Capture current proxy settings for backup
    pub fn backup_proxy_settings() -> ProxySettingsBackup {
        ProxySettingsBackup {
            proxy_enable: Self::read_internet_dword("ProxyEnable"),
            proxy_server: Self::read_internet_string("ProxyServer"),
            proxy_override: Self::read_internet_string("ProxyOverride"),
        }
    }

    /// Restore previous proxy settings from backup
    pub fn restore_proxy_settings(backup: &ProxySettingsBackup) -> Result<(), String> {
        if let Some(enable) = backup.proxy_enable {
            let _ = Self::write_internet_dword("ProxyEnable", enable);
        } else {
            let _ = Self::write_internet_dword("ProxyEnable", 0);
        }

        if let Some(ref server) = backup.proxy_server {
            let _ = Self::write_internet_string("ProxyServer", server);
        }

        if let Some(ref override_val) = backup.proxy_override {
            let _ = Self::write_internet_string("ProxyOverride", override_val);
        }

        Ok(())
    }
}
