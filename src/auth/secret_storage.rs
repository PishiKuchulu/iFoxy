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
#[allow(dead_code)] // used by the Windows DPAPI module and the test fallback
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

#[cfg(all(not(windows), not(target_os = "linux"), test))]
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

/// Linux secret protection: ChaCha20-Poly1305 (via ring) with a random
/// per-user key stored next to the session file, both files mode 0600.
/// This matches DPAPI's user-scope threat model — secrets are encrypted
/// at rest and unreadable to other users; it does not protect against
/// malware running as the same user, exactly like DPAPI.
#[cfg(target_os = "linux")]
mod dpapi {
    use super::*;
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
    use ring::rand::{SecureRandom, SystemRandom};

    const HEADER: &[u8] = b"ENC2:";
    const NONCE_LEN: usize = 12;
    const KEY_LEN: usize = 32;

    fn key_path() -> PathBuf {
        crate::paths::config_dir().join("session.key")
    }

    /// Read the key file, tolerating a concurrent creator's brief
    /// write window: `create_new` makes the file exist (empty) a
    /// moment before `write_all` lands, and a reader in that window
    /// must not mistake the in-flight key for corruption. A file that
    /// is still the wrong length after the retry window IS corruption
    /// (S3c) and errors. Returns Ok(None) when the file is absent.
    fn read_key_file(path: &std::path::Path) -> Result<Option<[u8; KEY_LEN]>, SecretError> {
        for attempt in 0..100 {
            match std::fs::read(path) {
                Ok(existing) => {
                    if existing.len() == KEY_LEN {
                        let mut key = [0u8; KEY_LEN];
                        key.copy_from_slice(&existing);
                        return Ok(Some(key));
                    }
                    if attempt < 99 {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    // A present-but-wrong key file is corruption, not a
                    // missing key: regenerating here (the old behavior
                    // on ANY error) silently orphaned the stored session
                    // (external review, S3c).
                    return Err(SecretError::Dpapi("Corrupt key file".into()));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }
        unreachable!()
    }

    fn load_or_create_key() -> Result<[u8; KEY_LEN], SecretError> {
        let path = key_path();
        match read_key_file(&path) {
            Ok(Some(key)) => Ok(key),
            Ok(None) => {
                let rng = SystemRandom::new();
                let mut key = [0u8; KEY_LEN];
                rng.fill(&mut key)
                    .map_err(|_| SecretError::Dpapi("RNG failure".into()))?;
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                // Create with mode 0600 atomically (create_new): no
                // write-then-chmod window where the key sits at umask
                // permissions (S3b), and two racing creators cannot
                // clobber each other — the loser re-reads the winner's
                // key (S3c).
                use std::io::Write as _;
                use std::os::unix::fs::OpenOptionsExt;
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                {
                    Ok(mut f) => {
                        f.write_all(&key)?;
                        f.sync_all()?;
                        Ok(key)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        load_key()
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Delete the key file (used by SecretStore::clear): a leftover key
    /// with no session is dead weight that also lets a later, unrelated
    /// session.enc be attempted against it (external review, S3e).
    pub fn remove_key_file() {
        let path = key_path();
        if path.exists() {
            if let Ok(meta) = std::fs::metadata(&path) {
                if meta.len() > 0 {
                    let _ = std::fs::write(&path, vec![0u8; meta.len() as usize]);
                }
            }
            let _ = std::fs::remove_file(&path);
        }
    }

    fn load_key() -> Result<[u8; KEY_LEN], SecretError> {
        match read_key_file(&key_path())? {
            Some(key) => Ok(key),
            None => Err(std::io::Error::from(std::io::ErrorKind::NotFound).into()),
        }
    }

    pub fn encrypt_bytes(plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        let key_bytes = load_or_create_key()?;
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| SecretError::Dpapi("Invalid key".into()))?;
        let key = LessSafeKey::new(unbound);
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| SecretError::Dpapi("RNG failure".into()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| SecretError::Dpapi("Encryption failed".into()))?;
        let mut out = Vec::with_capacity(HEADER.len() + NONCE_LEN + in_out.len());
        out.extend_from_slice(HEADER);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&in_out);
        Ok(out)
    }

    pub fn decrypt_bytes(ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
        if !ciphertext.starts_with(HEADER) || ciphertext.len() < HEADER.len() + NONCE_LEN {
            return Err(SecretError::Dpapi("Invalid ciphertext header".into()));
        }
        let key_bytes = load_key()?;
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| SecretError::Dpapi("Invalid key".into()))?;
        let key = LessSafeKey::new(unbound);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&ciphertext[HEADER.len()..HEADER.len() + NONCE_LEN]);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = ciphertext[HEADER.len() + NONCE_LEN..].to_vec();
        let plain = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| SecretError::Dpapi("Decryption failed".into()))?;
        Ok(plain.to_vec())
    }
}

#[cfg(all(not(windows), not(target_os = "linux"), not(test)))]
compile_error!("iFoxy requires Windows DPAPI or the Linux AEAD store for production secret storage. Other platforms are only allowed under test.");

pub struct SecretStore {
    storage_path: PathBuf,
}

impl SecretStore {
    pub fn new() -> Self {
        let dir = crate::paths::config_dir();
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

        // Atomic write (tmp + fsync + rename) with mode 0600 from
        // creation: a crash mid-write can no longer leave a torn
        // session file, and there is no write-then-chmod window at
        // umask permissions (external review, S3b/S3d). Windows keeps
        // the plain write (DPAPI blob; ACLs come from the profile dir).
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt;
            let tmp_path = self.storage_path.with_extension("tmp");
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(&encrypted)?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp_path, &self.storage_path)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&self.storage_path, &encrypted)?;
        }
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
        #[cfg(target_os = "linux")]
        {
            // Only the default store owns the key lifecycle: a
            // with_path store (tests, tooling) must not delete the key
            // the real session file still depends on.
            if self.storage_path == crate::paths::config_dir().join("session.enc") {
                dpapi::remove_key_file();
            }
        }
        Ok(())
    }
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new()
    }
}
