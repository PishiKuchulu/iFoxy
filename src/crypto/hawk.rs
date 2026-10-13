use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

/// Global clock skew compensation in seconds (M7)
static CLOCK_SKEW_SECONDS: AtomicI64 = AtomicI64::new(0);

#[derive(Error, Debug)]
pub enum HawkError {
    #[error("Invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("HMAC initialization failed: {0}")]
    Hmac(String),
}

/// Set clock skew offset in seconds
pub fn set_clock_skew_offset(offset_secs: i64) {
    CLOCK_SKEW_SECONDS.store(offset_secs, Ordering::SeqCst);
}

/// Reset clock skew offset to 0
pub fn reset_clock_skew_offset() {
    CLOCK_SKEW_SECONDS.store(0, Ordering::SeqCst);
}

/// Get current clock skew offset
pub fn get_clock_skew_offset() -> i64 {
    CLOCK_SKEW_SECONDS.load(Ordering::SeqCst)
}

/// Adjust clock skew based on server response header Server-Timestamp or WWW-Authenticate Hawk (M7)
pub fn update_clock_skew_from_server(server_timestamp_secs: u64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let offset = server_timestamp_secs as i64 - now as i64;
    tracing::info!("Compensating Hawk clock skew by {} seconds", offset);
    set_clock_skew_offset(offset);
}

pub fn check_response_for_clock_skew(headers: &reqwest::header::HeaderMap) {
    if let Some(ts_val) = headers
        .get("server-timestamp")
        .and_then(|v| v.to_str().ok())
    {
        if let Ok(ts) = ts_val.parse::<u64>() {
            update_clock_skew_from_server(ts);
            return;
        }
    }

    if let Some(auth_val) = headers
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(ts_idx) = auth_val.find("ts=\"") {
            let remainder = &auth_val[ts_idx + 4..];
            if let Some(end_quote) = remainder.find('"') {
                if let Ok(ts) = remainder[..end_quote].parse::<u64>() {
                    update_clock_skew_from_server(ts);
                }
            }
        }
    }
}

/// Generates a Hawk Authorization header matching Mozilla FxA specification with custom timestamp and nonce (M7)
pub fn generate_hawk_header_with_ts(
    method: &str,
    target_url: &str,
    token_id: &str,
    hmac_key: &[u8],
    body: &[u8],
    custom_ts: Option<&str>,
    custom_nonce: Option<&str>,
) -> Result<String, HawkError> {
    let url = Url::parse(target_url)?;

    let ts = match custom_ts {
        Some(t) => t.to_string(),
        None => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let adjusted = (now + CLOCK_SKEW_SECONDS.load(Ordering::SeqCst)).max(0) as u64;
            adjusted.to_string()
        }
    };

    let nonce = match custom_nonce {
        Some(n) => n.to_string(),
        None => {
            let mut nonce_bytes = [0u8; 6];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            URL_SAFE_NO_PAD.encode(nonce_bytes)
        }
    };

    let path = match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    };
    let host = url.host_str().unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(443).to_string();

    let mut payload_hash = String::new();
    if !body.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(b"hawk.1.payload\napplication/json\n");
        hasher.update(body);
        hasher.update(b"\n");
        payload_hash = STANDARD.encode(hasher.finalize());
    }

    let normalized = format!(
        "hawk.1.header\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n\n",
        ts,
        nonce,
        method.to_uppercase(),
        path,
        host,
        port,
        payload_hash
    );

    let mut mac =
        HmacSha256::new_from_slice(hmac_key).map_err(|e| HawkError::Hmac(e.to_string()))?;
    mac.update(normalized.as_bytes());
    let mac_b64 = STANDARD.encode(mac.finalize().into_bytes());

    let mut header = format!(
        "Hawk id=\"{}\", ts=\"{}\", nonce=\"{}\", mac=\"{}\"",
        token_id, ts, nonce, mac_b64
    );
    if !payload_hash.is_empty() {
        header.push_str(&format!(", hash=\"{}\"", payload_hash));
    }

    Ok(header)
}

/// Generates a Hawk Authorization header matching Mozilla FxA specification
pub fn generate_hawk_header(
    method: &str,
    target_url: &str,
    token_id: &str,
    hmac_key: &[u8],
    body: &[u8],
) -> Result<String, HawkError> {
    generate_hawk_header_with_ts(method, target_url, token_id, hmac_key, body, None, None)
}
