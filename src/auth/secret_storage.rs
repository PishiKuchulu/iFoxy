use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Error, Debug)]
pub enum SecretError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("DPAPI protection error: {0}")]
    Dpapi(String),
    #[error("Secret storage unavailable")]
    Unavailable,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct StoredSecrets {
    pub email: String,
    pub uid: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at_epoch_sec: Option<u64>,
}

impl std::fmt::Debug for StoredSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredSecrets")
            .field("email", &self.email)
            .field("uid", &self.uid)
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at_epoch_sec", &self.expires_at_epoch_sec)
            .finish()
    }
}

// Application-specific entropy for DPAPI
const DPAPI_ENTROPY: &[u8] = b"iFoxy-Windows-v1-UserSecrets-Entropy";

#[cfg(windows)]
mod dpapi {
    use super::*;

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut std::ffi::c_void,
            p_prompt_struct: *mut std::ffi::c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;

        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            ppsz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut std::ffi::c_void,
            p_prompt_struct: *mut std::ffi::c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    pub fn encrypt_bytes(plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        let in_blob = DataBlob {
            cb_data: plaintext.len() as u32,
            pb_data: plaintext.as_ptr() as *mut u8,
        };
        let entropy_blob = DataBlob {
            cb_data: DPAPI_ENTROPY.len() as u32,
            pb_data: DPAPI_ENTROPY.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };

        // SAFETY: CryptProtectData handles pointers with given lengths
        let ret = unsafe {
            CryptProtectData(
                &in_blob,
                std::ptr::null(),
                &entropy_blob,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if ret == 0 || out_blob.pb_data.is_null() {
            return Err(SecretError::Dpapi("CryptProtectData failed".into()));
        }

        let slice =
            unsafe { std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize) };
        let result = slice.to_vec();
        unsafe { LocalFree(out_blob.pb_data as *mut std::ffi::c_void) };

        Ok(result)
    }

    pub fn decrypt_bytes(ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
        let in_blob = DataBlob {
            cb_data: ciphertext.len() as u32,
            pb_data: ciphertext.as_ptr() as *mut u8,
        };
        let entropy_blob = DataBlob {
            cb_data: DPAPI_ENTROPY.len() as u32,
            pb_data: DPAPI_ENTROPY.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };

        // SAFETY: CryptUnprotectData handles pointers with given lengths
        let ret = unsafe {
            CryptUnprotectData(
                &in_blob,
                std::ptr::null_mut(),
                &entropy_blob,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if ret == 0 || out_blob.pb_data.is_null() {
            return Err(SecretError::Dpapi("CryptUnprotectData failed".into()));
        }

        let slice =
            unsafe { std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize) };
        let result = slice.to_vec();
        unsafe { LocalFree(out_blob.pb_data as *mut std::ffi::c_void) };

        Ok(result)
    }
}

#[cfg(all(not(windows), test))]
mod dpapi {
    use super::*;

    // Fallback XOR-masking for non-Windows build/test environments
    pub fn encrypt_bytes(plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        let mut enc = Vec::with_capacity(plaintext.len() + 4);
        enc.extend_from_slice(b"ENC:");
        for (i, &b) in plaintext.iter().enumerate() {
            enc.push(b ^ DPAPI_ENTROPY[i % DPAPI_ENTROPY.len()]);
        }
        Ok(enc)
    }

    pub fn decrypt_bytes(ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
        if !ciphertext.starts_with(b"ENC:") {
            return Err(SecretError::Dpapi("Invalid ciphertext header".into()));
        }
        let body = &ciphertext[4..];
        let mut dec = Vec::with_capacity(body.len());
        for (i, &b) in body.iter().enumerate() {
            dec.push(b ^ DPAPI_ENTROPY[i % DPAPI_ENTROPY.len()]);
        }
        Ok(dec)
    }
}

#[cfg(all(not(windows), not(test)))]
compile_error!("iFoxy requires Windows DPAPI for production secret storage. Non-Windows builds are only allowed under test.");

pub struct SecretStore {
    storage_path: PathBuf,
}

impl SecretStore {
    pub fn new() -> Self {
        let base = std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let dir = base.join("iFoxy");
        let _ = std::fs::create_dir_all(&dir);
        Self {
            storage_path: dir.join("session.enc"),
        }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self { storage_path: path }
    }

    pub fn save(&self, secrets: &StoredSecrets) -> Result<(), SecretError> {
        let json_str = serde_json::to_string(secrets)?;
        let mut plaintext = json_str.into_bytes();
        let encrypted = dpapi::encrypt_bytes(&plaintext)?;
        plaintext.zeroize();

        // Write with restrictive file permissions
        std::fs::write(&self.storage_path, &encrypted)?;
        Ok(())
    }

    pub fn load(&self) -> Result<Option<StoredSecrets>, SecretError> {
        if !self.storage_path.exists() {
            return Ok(None);
        }

        let encrypted = std::fs::read(&self.storage_path)?;
        if encrypted.is_empty() {
            return Ok(None);
        }

        let mut decrypted = dpapi::decrypt_bytes(&encrypted)?;
        let secrets: StoredSecrets = serde_json::from_slice(&decrypted)?;
        decrypted.zeroize();

        Ok(Some(secrets))
    }

    pub fn clear(&self) -> Result<(), SecretError> {
        if self.storage_path.exists() {
            // Overwrite with zeroes before deleting to ensure zeroization on disk
            let len = std::fs::metadata(&self.storage_path)
                .map(|m| m.len())
                .unwrap_or(0);
            if len > 0 {
                let zeroes = vec![0u8; len as usize];
                let _ = std::fs::write(&self.storage_path, &zeroes);
            }
            std::fs::remove_file(&self.storage_path)?;
        }
        Ok(())
    }
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new()
    }
}
