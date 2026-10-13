use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

const PROTOCOL_VERSION: &str = "identity.mozilla.com/picl/v1/";
const PBKDF2_ROUNDS: u32 = 1000;
const STRETCHED_PW_LEN: usize = 32;
const HKDF_LEN: usize = 32;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("KDF error: {0}")]
    Kdf(String),
    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// Derives quickStretch from email and password using PBKDF2-HMAC-SHA256
pub fn derive_quick_stretch(
    email: &str,
    password: &str,
) -> Result<[u8; STRETCHED_PW_LEN], CryptoError> {
    let salt = format!("{}quickStretch:{}", PROTOCOL_VERSION, email);
    let mut out = [0u8; STRETCHED_PW_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ROUNDS,
        &mut out,
    );
    Ok(out)
}

/// Derives authPW for Firefox Accounts login
pub fn derive_auth_pw(email: &str, password: &str) -> Result<String, CryptoError> {
    let quick_stretched = derive_quick_stretch(email, password)?;
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &quick_stretched);
    let mut okm = [0u8; HKDF_LEN];
    let info = format!("{}authPW", PROTOCOL_VERSION);
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|e| CryptoError::Kdf(format!("HKDF expand failed: {:?}", e)))?;
    Ok(hex::encode(okm))
}

/// Derives Hawk credentials (token_id, hmac_key) from sessionToken hex
pub fn derive_hawk_credentials(session_token_hex: &str) -> Result<(String, [u8; 32]), CryptoError> {
    let session_token = hex::decode(session_token_hex)?;
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &session_token);
    let mut okm = [0u8; 64];
    let info = format!("{}sessionToken", PROTOCOL_VERSION);
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|e| CryptoError::Kdf(format!("HKDF expand failed: {:?}", e)))?;

    let token_id = hex::encode(&okm[0..32]);
    let mut hmac_key = [0u8; 32];
    hmac_key.copy_from_slice(&okm[32..64]);
    Ok((token_id, hmac_key))
}
