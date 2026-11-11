use base64::Engine as _;
use crate::crypto::fxa_kdf::{derive_auth_pw, derive_hawk_credentials, CryptoError};
use crate::crypto::hawk::{generate_hawk_header, HawkError};
use rand::RngCore;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroize;

const FXA_AUTH_SERVER: &str = "https://api.accounts.firefox.com/v1";
/// The dedicated OAuth host: the token call of the PKCE grant goes here.
const FXA_OAUTH_SERVER: &str = "https://oauth.accounts.firefox.com/v1";
const FIREFOX_CLIENT_ID: &str = "5882386c6d801776";
const OAUTH_SCOPE: &str = "profile https://identity.mozilla.com/apps/vpn";
pub const MOZILLA_VPN_USER_AGENT: &str = "MozillaVPN/2.35.0 (sys:linux; iap:true)";

/// A random RFC 7636 code verifier or OAuth state: URL-safe base64 without
/// padding over `byte_count` random bytes. 32 bytes gives the 43-character
/// verifier that is the RFC's minimum length.
fn random_base64url(byte_count: usize) -> String {
    let mut bytes = vec![0u8; byte_count];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

/// RFC 7636 S256 code challenge: BASE64URL(SHA-256(ASCII(verifier))).
fn pkce_challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_slice())
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Hawk error: {0}")]
    Hawk(#[from] HawkError),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API error ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at_epoch_seconds: u64,
}

#[derive(Debug)]
pub enum LoginResult {
    Success(OAuthTokens),
    Requires2Fa { session_token: String },
}

pub struct FxaClient {
    client: Client,
    auth_server: String,
}

impl FxaClient {
    pub fn new() -> Self {
        Self {
            client: crate::http_client::create_default_client().unwrap_or_else(|e| {
                tracing::warn!("Failed to build default HTTP client: {:?}", e);
                Client::new()
            }),
            auth_server: FXA_AUTH_SERVER.to_string(),
        }
    }

    pub fn with_client(client: Client) -> Self {
        Self {
            client,
            auth_server: FXA_AUTH_SERVER.to_string(),
        }
    }

    pub fn with_client_and_server(client: Client, auth_server: &str) -> Self {
        Self {
            client,
            auth_server: auth_server.trim_end_matches('/').to_string(),
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn login(&self, email: &str, password: &str) -> Result<LoginResult, AuthError> {
        match self.login_once(email, password).await {
            Err(AuthError::Api { status, message }) => {
                // FxA errno 120 "Incorrect email case": the account's
                // canonical email casing differs from what the user
                // typed, and the response body carries the canonical
                // address. Retry once with it instead of failing the
                // login (external review, S8).
                if status == 400 {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&message) {
                        if v["errno"].as_u64() == Some(120) {
                            if let Some(canonical) = v["email"].as_str() {
                                if canonical != email {
                                    return self.login_once(canonical, password).await;
                                }
                            }
                        }
                    }
                }
                Err(AuthError::Api { status, message })
            }
            other => other,
        }
    }

    async fn login_once(&self, email: &str, password: &str) -> Result<LoginResult, AuthError> {
        let mut auth_pw = derive_auth_pw(email, password)?;
        let url = format!("{}/account/login", self.auth_server);

        let body = serde_json::json!({
            "email": email,
            "authPW": auth_pw,
            "verificationMethod": "email-2fa"
        });
        // The derived password equivalent has done its job once it is
        // in the request body; wipe our copy (external review, S9).
        auth_pw.zeroize();

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(MOZILLA_VPN_USER_AGENT));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let mut body = body;
        let res = self
            .client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await?;
        // The request has been serialized and sent; shrink the authPW
        // copy inside the JSON body to an empty string so it does not
        // sit in memory for the rest of the login flow (M-5; the
        // serialized copy inside the HTTP stack is beyond our reach).
        body["authPW"] = serde_json::Value::String(String::new());

        let status = res.status();
        crate::crypto::hawk::check_response_for_clock_skew(res.headers());
        let text = res.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AuthError::Api {
                status: status.as_u16(),
                message: text,
            });
        }

        let json: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| AuthError::InvalidState(e.to_string()))?;

        let session_token = json["sessionToken"]
            .as_str()
            .ok_or_else(|| AuthError::InvalidState("Missing sessionToken".to_string()))?
            .to_string();

        let verified = json["verified"].as_bool().unwrap_or(false);
        if !verified {
            Ok(LoginResult::Requires2Fa { session_token })
        } else {
            let tokens = self.exchange_oauth(&session_token).await?;
            Ok(LoginResult::Success(tokens))
        }
    }

    pub async fn verify_2fa(
        &self,
        session_token: &str,
        code: &str,
    ) -> Result<OAuthTokens, AuthError> {
        let url = format!("{}/session/verify_code", self.auth_server);
        let body = serde_json::json!({ "code": code });
        let body_bytes = serde_json::to_vec(&body).unwrap_or_default();

        let (token_id, mut hmac_key) = derive_hawk_credentials(session_token)?;
        let hawk_header = generate_hawk_header("POST", &url, &token_id, &hmac_key, &body_bytes)?;
        hmac_key.zeroize();

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(MOZILLA_VPN_USER_AGENT));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&hawk_header)
                .map_err(|e| AuthError::InvalidState(e.to_string()))?,
        );

        let res = self
            .client
            .post(&url)
            .headers(headers)
            .body(body_bytes)
            .send()
            .await?;

        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AuthError::Api {
                status: status.as_u16(),
                message: text,
            });
        }

        self.exchange_oauth(session_token).await
    }

    /// POST a JSON body signed with Hawk credentials derived from the session
    /// token, and return the parsed JSON response.
    async fn post_hawk_json(
        &self,
        url: &str,
        session_token: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, AuthError> {
        let body_bytes = serde_json::to_vec(body).unwrap_or_default();

        let (token_id, mut hmac_key) = derive_hawk_credentials(session_token)?;
        let hawk_header = generate_hawk_header("POST", url, &token_id, &hmac_key, &body_bytes)?;
        hmac_key.zeroize();

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(MOZILLA_VPN_USER_AGENT));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&hawk_header)
                .map_err(|e| AuthError::InvalidState(e.to_string()))?,
        );

        let res = self
            .client
            .post(url)
            .headers(headers)
            .body(body_bytes)
            .send()
            .await?;
        let status = res.status();
        crate::crypto::hawk::check_response_for_clock_skew(res.headers());
        let text = res.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AuthError::Api {
                status: status.as_u16(),
                message: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| AuthError::InvalidState(e.to_string()))
    }

    /// POST an unauthenticated JSON body and return the parsed JSON response.
    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, AuthError> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(MOZILLA_VPN_USER_AGENT));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let res = self
            .client
            .post(url)
            .headers(headers)
            .json(body)
            .send()
            .await?;
        let status = res.status();
        crate::crypto::hawk::check_response_for_clock_skew(res.headers());
        let text = res.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AuthError::Api {
                status: status.as_u16(),
                message: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| AuthError::InvalidState(e.to_string()))
    }

    /// Trade the session token for OAuth tokens: the PKCE
    /// authorization-code grant first, with the legacy `fxa-credentials`
    /// grant as a fallback for unexpected failures, mirroring the
    /// Android client.
    pub async fn exchange_oauth(&self, session_token: &str) -> Result<OAuthTokens, AuthError> {
        match self.exchange_oauth_pkce(session_token).await {
            Ok(tokens) => Ok(tokens),
            Err(failure) => {
                tracing::warn!(
                    "PKCE token exchange failed ({failure}); trying the legacy fxa-credentials grant"
                );
                self.exchange_oauth_legacy(session_token).await
            }
        }
    }

    /// Authorization-code grant with PKCE, the flow the Firefox browser itself
    /// uses: the session token is traded for a one-time code (Hawk-signed),
    /// and the code plus our verifier is traded for tokens at the dedicated
    /// OAuth host.
    async fn exchange_oauth_pkce(&self, session_token: &str) -> Result<OAuthTokens, AuthError> {
        let verifier = random_base64url(32);
        let state = random_base64url(16);

        let authorize_url = format!("{}/oauth/authorization", self.auth_server);
        let authorize_body = serde_json::json!({
            "client_id": FIREFOX_CLIENT_ID,
            "response_type": "code",
            "scope": OAUTH_SCOPE,
            "state": &state,
            "access_type": "offline",
            "code_challenge": pkce_challenge_s256(&verifier),
            "code_challenge_method": "S256"
        });
        let authorization = self
            .post_hawk_json(&authorize_url, session_token, &authorize_body)
            .await?;
        let code = authorization["code"].as_str().unwrap_or_default();
        if code.is_empty() || authorization["state"].as_str() != Some(state.as_str()) {
            return Err(AuthError::InvalidState(
                "Invalid OAuth authorization response".to_string(),
            ));
        }

        let token_url = format!("{}/token", FXA_OAUTH_SERVER);
        let token_body = serde_json::json!({
            "client_id": FIREFOX_CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": &verifier
        });
        let json = self.post_json(&token_url, &token_body).await?;
        Self::tokens_from_json(&json)
    }

    /// The legacy `fxa-credentials` grant, kept as the fallback for when
    /// the PKCE exchange fails unexpectedly.
    async fn exchange_oauth_legacy(&self, session_token: &str) -> Result<OAuthTokens, AuthError> {
        let url = format!("{}/oauth/token", self.auth_server);
        let body = serde_json::json!({
            "client_id": FIREFOX_CLIENT_ID,
            "grant_type": "fxa-credentials",
            "scope": OAUTH_SCOPE,
            "access_type": "offline"
        });
        let json = self.post_hawk_json(&url, session_token, &body).await?;
        Self::tokens_from_json(&json)
    }

    /// Build the token set from a token-endpoint JSON response.
    fn tokens_from_json(json: &serde_json::Value) -> Result<OAuthTokens, AuthError> {
        let access_token = json["access_token"]
            .as_str()
            .ok_or_else(|| AuthError::InvalidState("Missing access_token".to_string()))?
            .to_string();
        let refresh_token = json["refresh_token"].as_str().map(|s| s.to_string());
        let expires_in = json["expires_in"].as_u64().unwrap_or(86400);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(OAuthTokens {
            access_token,
            refresh_token,
            expires_at_epoch_seconds: now + expires_in,
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> Result<OAuthTokens, AuthError> {
        let url = format!("{}/oauth/token", self.auth_server);
        let body = serde_json::json!({
            "client_id": FIREFOX_CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": OAUTH_SCOPE
        });

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(MOZILLA_VPN_USER_AGENT));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let res = self
            .client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        let status = res.status();
        crate::crypto::hawk::check_response_for_clock_skew(res.headers());
        let text = res.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AuthError::Api {
                status: status.as_u16(),
                message: text,
            });
        }

        let json: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| AuthError::InvalidState(e.to_string()))?;

        let access_token = json["access_token"]
            .as_str()
            .ok_or_else(|| AuthError::InvalidState("Missing access_token".to_string()))?
            .to_string();

        let new_refresh_token = json["refresh_token"]
            .as_str()
            .map(|s| s.to_string())
            .or_else(|| Some(refresh_token.to_string()));

        let expires_in = json["expires_in"].as_u64().unwrap_or(86400);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(OAuthTokens {
            access_token,
            refresh_token: new_refresh_token,
            expires_at_epoch_seconds: now + expires_in,
        })
    }

    pub async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        let url = format!("{}/oauth/destroy", self.auth_server);
        let body = serde_json::json!({
            "client_id": FIREFOX_CLIENT_ID,
            "token": token
        });

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(MOZILLA_VPN_USER_AGENT));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        // The result used to be discarded entirely, so callers logged
        // "revoked" even when the destroy call never landed (external
        // review, S7). Surface transport and HTTP failures.
        let res = self
            .client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await?;
        let status = res.status();
        if status.is_success() {
            Ok(())
        } else {
            let text = res.text().await.unwrap_or_default();
            Err(AuthError::Api {
                status: status.as_u16(),
                message: text,
            })
        }
    }
}

impl Default for FxaClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod pkce_tests {
    use super::{pkce_challenge_s256, random_base64url};

    #[test]
    fn s256_challenge_matches_rfc7636_appendix_b() {
        assert_eq!(
            pkce_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn verifier_from_32_bytes_is_43_url_safe_chars() {
        let verifier = random_base64url(32);
        assert_eq!(verifier.len(), 43);
        assert!(verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }
}
