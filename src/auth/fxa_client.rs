use crate::crypto::fxa_kdf::{derive_auth_pw, derive_hawk_credentials, CryptoError};
use crate::crypto::hawk::{generate_hawk_header, HawkError};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroize;

const FXA_AUTH_SERVER: &str = "https://api.accounts.firefox.com/v1";
const FIREFOX_CLIENT_ID: &str = "5882386c6d801776";
const OAUTH_SCOPE: &str = "profile https://identity.mozilla.com/apps/vpn";
pub const MOZILLA_VPN_USER_AGENT: &str = "MozillaVPN/2.35.0 (sys:linux; iap:true)";

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

        let (token_id, hmac_key) = derive_hawk_credentials(session_token)?;
        let hawk_header = generate_hawk_header("POST", &url, &token_id, &hmac_key, &body_bytes)?;

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

    pub async fn exchange_oauth(&self, session_token: &str) -> Result<OAuthTokens, AuthError> {
        let url = format!("{}/oauth/token", self.auth_server);
        let body = serde_json::json!({
            "client_id": FIREFOX_CLIENT_ID,
            "grant_type": "fxa-credentials",
            "scope": OAUTH_SCOPE,
            "access_type": "offline"
        });
        let body_bytes = serde_json::to_vec(&body).unwrap_or_default();

        let (token_id, hmac_key) = derive_hawk_credentials(session_token)?;
        let hawk_header = generate_hawk_header("POST", &url, &token_id, &hmac_key, &body_bytes)?;

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
