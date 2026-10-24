use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SecurityError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("Integrity check failed: expected hash {expected}, got {actual}")]
    IntegrityMismatch { expected: String, actual: String },
    #[error("Refusing execution from insecure/user-writable location: {0}")]
    InsecureLocation(String),
    #[error("Authenticode signature verification failed: WinVerifyTrust error 0x{0:08X}")]
    AuthenticodeFailed(u32),
}

impl From<std::io::Error> for SecurityError {
    fn from(e: std::io::Error) -> Self {
        SecurityError::Io(e.to_string())
    }
}

/// Normalizes a Windows path for prefix comparison: forward slashes become
/// backslashes, the `\\?\` verbatim prefix and trailing separators are
/// removed, and the result is lower-cased (Windows paths are case-insensitive).
fn normalize_windows_path(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\");
    let s = s.strip_prefix("\\\\?\\").unwrap_or(&s).to_string();
    s.trim_end_matches('\\').to_ascii_lowercase()
}

/// True if `path` is `root` itself or lies inside it.
pub fn is_path_under(path: &Path, root: &Path) -> bool {
    let p = normalize_windows_path(path);
    let r = normalize_windows_path(root);
    !r.is_empty() && (p == r || p.starts_with(&format!("{}\\", r)))
}

/// Directories that only administrators can write to by default.
pub fn trusted_install_roots() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
        .iter()
        .filter_map(|k| std::env::var_os(*k))
        .map(PathBuf::from)
        .collect()
}

pub fn is_secure_install_location(exe_dir: &Path, roots: &[PathBuf]) -> bool {
    // Canonicalize both sides first: the string-prefix comparison alone
    // trusted the path as spelled, so a symlink/junction inside a
    // trusted root (or `..` segments) could make a user-writable
    // directory look installed under Program Files (external review,
    // S5). Canonicalization resolves links and dot segments; fall back
    // to the raw path when it fails (e.g. a root that does not exist).
    let canon = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let exe = canon(exe_dir);
    roots.iter().any(|r| is_path_under(&exe, &canon(r)))
}

/// The application runs elevated and loads DLLs from its own directory. If
/// that directory is writable by a normal user, any local process can
/// replace a DLL or the executable and obtain Administrator rights (C3). A
/// hash check at startup cannot close this on its own: it is a
/// check-then-use race, and an import-time DLL is loaded before `main`
/// runs. The real protection is refusing to run from a location that only
/// administrators can write to, unless the operator explicitly opts in
/// (development or portable use).
pub fn check_install_location(exe_dir: &Path, allow_portable: bool) -> Result<(), SecurityError> {
    #[cfg(target_os = "linux")]
    {
        let _ = allow_portable;
        // Linux divergence (documented): there is no native Yes/No prompt
        // yet (the Windows one is a message box), and the distributed
        // tarball normally runs from the user's home — exiting here would
        // brick the normal install path. Installs under /usr or /opt are
        // root-owned by construction; anywhere else, warn loudly and run.
        let admin_owned = [Path::new("/usr"), Path::new("/opt")]
            .iter()
            .any(|r| exe_dir.starts_with(r));
        if !admin_owned {
            tracing::warn!(
                "iFoxy runs elevated from a user-writable location on Linux: {}. \
                 A local process running as your user could replace the binary and \
                 gain root at the next launch; prefer installing under /opt or /usr/local.",
                exe_dir.display()
            );
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        if allow_portable || is_secure_install_location(exe_dir, &trusted_install_roots()) {
            Ok(())
        } else {
            Err(SecurityError::InsecureLocation(
                exe_dir.display().to_string(),
            ))
        }
    }
}

pub const OFFICIAL_WEBVIEW2_LOADER_DLL_SHA256: &str =
    "86545b66cdb0603bc26b626fb9ad610cb6e71f28d468f5ea66df23b03dda96d5";

/// Kept for compatibility and tests — with the loader statically linked, a
/// stray `WebView2Loader.dll` next to the exe is suspicious rather than useful,
/// so we still reject a tampered copy when one is present.
pub fn verify_webview2_loader_dll_at(dir: &Path) -> Result<(), SecurityError> {
    let dll_path = dir.join("WebView2Loader.dll");
    if dll_path.exists() {
        verify_file_hash(&dll_path, OFFICIAL_WEBVIEW2_LOADER_DLL_SHA256)
    } else {
        Ok(())
    }
}

pub fn compute_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn verify_file_hash(path: &Path, expected_hash_hex: &str) -> Result<(), SecurityError> {
    let content = fs::read(path)?;
    let actual_hash = compute_sha256_hex(&content);
    if !actual_hash.eq_ignore_ascii_case(expected_hash_hex) {
        return Err(SecurityError::IntegrityMismatch {
            expected: expected_hash_hex.to_string(),
            actual: actual_hash,
        });
    }
    Ok(())
}

pub fn safe_write_and_verify(
    path: &Path,
    bytes: &[u8],
    expected_hash_hex: &str,
) -> Result<(), SecurityError> {
    let actual_bytes_hash = compute_sha256_hex(bytes);
    if !actual_bytes_hash.eq_ignore_ascii_case(expected_hash_hex) {
        return Err(SecurityError::IntegrityMismatch {
            expected: expected_hash_hex.to_string(),
            actual: actual_bytes_hash,
        });
    }

    // Write to temporary file first then atomic rename
    let tmp_path = path.with_extension("tmp_sec");
    fs::write(&tmp_path, bytes)?;

    // Verify written file before committing to destination
    verify_file_hash(&tmp_path, expected_hash_hex)?;
    fs::rename(&tmp_path, path)?;

    // Final verification of destination file
    verify_file_hash(path, expected_hash_hex)?;
    Ok(())
}

#[cfg(windows)]
#[repr(C)]
struct WintrustFileInfo {
    cb_struct: u32,
    pcwsz_file_path: *const u16,
    h_file: *mut std::ffi::c_void,
    pg_known_subject: *const windows_sys::core::GUID,
}

#[cfg(windows)]
const _: () = assert!(std::mem::size_of::<WintrustFileInfo>() == 32);

#[cfg(windows)]
#[repr(C)]
struct WintrustData {
    cb_struct: u32,
    p_policy_callback_data: *mut std::ffi::c_void,
    p_sip_client_data: *mut std::ffi::c_void,
    dw_ui_choice: u32,
    fdw_revocation_checks: u32,
    dw_union_choice: u32,
    p_file: *mut WintrustFileInfo,
    dw_state_action: u32,
    h_wvt_state_data: *mut std::ffi::c_void,
    pwsz_url_reference: *mut u16,
    dw_prov_flags: u32,
    dw_ui_context: u32,
    p_signature_settings: *mut std::ffi::c_void,
}

#[cfg(windows)]
const _: () = assert!(std::mem::size_of::<WintrustData>() == 88);

#[cfg(windows)]
const WINTRUST_ACTION_GENERIC_VERIFY_V2: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0x00aac56b,
    data2: 0xcd44,
    data3: 0x11d0,
    data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};

#[cfg(windows)]
const WTD_UI_NONE: u32 = 2;
#[cfg(windows)]
const WTD_REVOKE_NONE: u32 = 0;
#[cfg(windows)]
const WTD_CHOICE_FILE: u32 = 1;
#[cfg(windows)]
const WTD_STATEACTION_VERIFY: u32 = 1;
#[cfg(windows)]
const WTD_STATEACTION_CLOSE: u32 = 2;
#[cfg(windows)]
const WTD_SAFER_FLAG: u32 = 0x100;

#[cfg(windows)]
#[link(name = "wintrust")]
extern "system" {
    fn WinVerifyTrust(
        hwnd: *mut std::ffi::c_void,
        pgactionid: *const windows_sys::core::GUID,
        pwvtdata: *mut std::ffi::c_void,
    ) -> i32;
}

#[cfg(windows)]
pub fn verify_authenticode_signature(path: &Path) -> Result<(), SecurityError> {
    use std::os::windows::ffi::OsStrExt;
    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info: WintrustFileInfo = unsafe { std::mem::zeroed() };
    file_info.cb_struct = std::mem::size_of::<WintrustFileInfo>() as u32;
    file_info.pcwsz_file_path = path_wide.as_ptr();

    let mut trust_data: WintrustData = unsafe { std::mem::zeroed() };
    trust_data.cb_struct = std::mem::size_of::<WintrustData>() as u32;
    trust_data.dw_union_choice = WTD_CHOICE_FILE;
    trust_data.p_file = &mut file_info;
    trust_data.dw_ui_choice = WTD_UI_NONE;
    trust_data.fdw_revocation_checks = WTD_REVOKE_NONE;
    trust_data.dw_state_action = WTD_STATEACTION_VERIFY;
    trust_data.dw_prov_flags = WTD_SAFER_FLAG;

    // SAFETY: file_info and trust_data point to stack memory valid for the call duration.
    let status = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            &mut trust_data as *mut _ as *mut std::ffi::c_void,
        )
    };

    // Release state data allocated by provider
    trust_data.dw_state_action = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            &mut trust_data as *mut _ as *mut std::ffi::c_void,
        );
    }

    if status == 0 {
        Ok(())
    } else {
        Err(SecurityError::AuthenticodeFailed(status as u32))
    }
}

#[cfg(not(windows))]
pub fn verify_authenticode_signature(_path: &Path) -> Result<(), SecurityError> {
    Ok(())
}

#[cfg(windows)]
pub fn enforce_safe_dll_search() {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetDefaultDllDirectories(directory_flags: u32) -> i32;
    }
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x00000800;
    unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
}

#[cfg(not(windows))]
pub fn enforce_safe_dll_search() {
    // No-op for non-Windows targets
}

pub struct SingleInstanceGuard {
    #[cfg(windows)]
    handle: *mut std::ffi::c_void,
    #[cfg(target_os = "linux")]
    _lock_file: Option<fs::File>,
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            #[link(name = "kernel32")]
            extern "system" {
                fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
            }
            if !self.handle.is_null() {
                unsafe {
                    CloseHandle(self.handle);
                }
            }
        }
    }
}

#[cfg(windows)]
pub fn acquire_single_instance(mutex_name: &str) -> Option<SingleInstanceGuard> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateMutexW(
            lp_mutex_attributes: *mut std::ffi::c_void,
            b_initial_owner: i32,
            lp_name: *const u16,
        ) -> *mut std::ffi::c_void;
        fn GetLastError() -> u32;
    }
    const ERROR_ALREADY_EXISTS: u32 = 183;
    let name_wide: Vec<u16> = std::ffi::OsStr::new(mutex_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 0, name_wide.as_ptr()) };
    if handle.is_null() || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        None
    } else {
        Some(SingleInstanceGuard { handle })
    }
}

/// Linux single instance: an flock held for the process lifetime on a
/// lockfile in the runtime dir. Dropping the guard closes the file and
/// releases the lock.
#[cfg(target_os = "linux")]
pub fn acquire_single_instance(_mutex_name: &str) -> Option<SingleInstanceGuard> {
    use std::os::unix::io::AsRawFd;
    // XDG_RUNTIME_DIR is per-user (mode 0700). The old fallback put the
    // lock in world-writable /tmp, where any local user could pre-create
    // and hold the file to block startup (external review, S5); fall
    // back to the user's own state dir instead.
    let dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(crate::paths::state_dir);
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("ifoxy.lock");
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .ok()?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return None;
    }
    Some(SingleInstanceGuard {
        _lock_file: Some(file),
    })
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn acquire_single_instance(_mutex_name: &str) -> Option<SingleInstanceGuard> {
    Some(SingleInstanceGuard {})
}

pub fn check_single_instance(mutex_name: &str) -> bool {
    acquire_single_instance(mutex_name).is_some()
}
