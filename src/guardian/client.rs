use super::challenge_solver::{ChallengeError, FastlyChallengeSolver};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const GUARDIAN_ENDPOINT_DEFAULT: &str = "https://vpn.mozilla.org";
pub const MOZILLA_VPN_USER_AGENT: &str = "MozillaVPN/2.35.0 (sys:linux; iap:true)";

#[derive(Error, Debug)]
pub enum GuardianError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Fastly Challenge error: {0}")]
    Challenge(#[from] ChallengeError),
    #[error("Access token invalid or rejected")]
    TokenInvalid,
    #[error("Monthly quota exceeded (429)")]
    QuotaExceeded,
    #[error("Guardian API error ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("Parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyPass {
    pub token: String,
    #[serde(default, alias = "expires_at")]
    pub expires_at_epoch_seconds: Option<u64>,
    #[serde(default)]
    pub quota_max: Option<u64>,
    #[serde(default)]
    pub quota_remaining: Option<u64>,
    #[serde(default)]
    pub quota_reset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    pub subscribed: bool,
    pub uid: String,
    pub max_bytes: Option<i64>,
    pub limited_bandwidth: bool,
    pub quota_remaining: Option<u64>,
}

pub struct GuardianClient {
    client: Client,
    solver: FastlyChallengeSolver,
    endpoint: String,
}

impl GuardianClient {
    pub fn new() -> Self {
        Self::with_endpoint(GUARDIAN_ENDPOINT_DEFAULT)
    }

    pub fn with_endpoint(endpoint: &str) -> Self {
        let client = crate::http_client::create_default_client().unwrap_or_else(|e| {
            tracing::warn!("Failed to build default HTTP client: {:?}", e);
            Client::builder()
                .cookie_store(true)
                .build()
                .unwrap_or_default()
        });
        let solver = FastlyChallengeSolver::with_client(client.clone());
        Self {
            client,
            solver,
            endpoint: endpoint.to_string(),
        }
    }

    pub fn with_client(client: Client) -> Self {
        Self::with_client_and_endpoint(client, GUARDIAN_ENDPOINT_DEFAULT)
    }

    pub fn with_client_and_endpoint(client: Client, endpoint: &str) -> Self {
        let solver = FastlyChallengeSolver::with_client(client.clone());
        Self {
            client,
            solver,
            endpoint: endpoint.to_string(),
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn fetch_proxy_pass(
        &self,
        endpoint: &str,
        access_token: &str,
    ) -> Result<ProxyPass, GuardianError> {
        let url = format!("{}/api/v1/fpn/token", endpoint.trim_end_matches('/'));

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(MOZILLA_VPN_USER_AGENT));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", access_token))
                .map_err(|e| GuardianError::Parse(e.to_string()))?,
        );

        let mut res = self
            .client
            .get(&url)
            .headers(headers.clone())
            .send()
            .await?;

        if res.status().as_u16() == 406 {
            self.solver
                .solve_and_install("https://api.accounts.firefox.com")
                .await?;
            res = self
                .client
                .get(&url)
                .headers(headers.clone())
                .send()
                .await?;
        }

        // If Guardian hasn't seen this session before, it returns 401/403 until activated
        if res.status().as_u16() == 401 || res.status().as_u16() == 403 {
            tracing::info!(
                "Guardian proxy pass returned {}, activating entitlement and retrying...",
                res.status()
            );
            if self.activate_guardian(endpoint, access_token).await.is_ok() {
                res = self
                    .client
                    .get(&url)
                    .headers(headers.clone())
                    .send()
                    .await?;
                if res.status().as_u16() == 406 {
                    self.solver
                        .solve_and_install("https://api.accounts.firefox.com")
                        .await?;
                    res = self.client.get(&url).headers(headers).send().await?;
                }
            }
        }

        match res.status().as_u16() {
            401 | 403 => return Err(GuardianError::TokenInvalid),
            429 => return Err(GuardianError::QuotaExceeded),
            s if !res.status().is_success() => {
                let msg = res.text().await.unwrap_or_default();
                return Err(GuardianError::Api {
                    status: s,
                    message: msg,
                });
            }
            _ => {}
        }

        let quota_max = res
            .headers()
            .get("X-Quota-Limit")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let quota_remaining = res
            .headers()
            .get("X-Quota-Remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let quota_reset = res
            .headers()
            .get("X-Quota-Reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body: serde_json::Value = res.json().await?;
        let token = body["token"]
            .as_str()
            .ok_or_else(|| {
                GuardianError::Parse("Missing token in proxy pass response".to_string())
            })?
            .to_string();

        let expires_at_epoch_seconds = body["expires_at"].as_u64();

        Ok(ProxyPass {
            token,
            expires_at_epoch_seconds,
            quota_max,
            quota_remaining,
            quota_reset,
        })
    }

    pub async fn fetch_user_info(
        &self,
        endpoint: &str,
        access_token: &str,
    ) -> Result<Entitlement, GuardianError> {
        let url = format!("{}/api/v1/fpn/status", endpoint.trim_end_matches('/'));

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(MOZILLA_VPN_USER_AGENT));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", access_token))
                .map_err(|e| GuardianError::Parse(e.to_string()))?,
        );

        let res = self.client.get(&url).headers(headers).send().await?;

        if !res.status().is_success() {
            return Err(GuardianError::Api {
                status: res.status().as_u16(),
                message: res.text().await.unwrap_or_default(),
            });
        }

        let body: serde_json::Value = res.json().await?;
        let subscribed = body["subscribed"].as_bool().unwrap_or(false);
        let uid = body["uid"].as_str().unwrap_or_default().to_string();
        let max_bytes = body["maxBytes"].as_i64();
        let limited_bandwidth = body["limited_bandwidth"].as_bool().unwrap_or(false);

        let quota_remaining = if limited_bandwidth {
            self.fetch_proxy_pass(endpoint, access_token)
                .await
                .ok()
                .and_then(|p| p.quota_remaining)
        } else {
            None
        };

        Ok(Entitlement {
            subscribed,
            uid,
            max_bytes,
            limited_bandwidth,
            quota_remaining,
        })
    }

    pub async fn activate_guardian(
        &self,
        endpoint: &str,
        access_token: &str,
    ) -> Result<Entitlement, GuardianError> {
        let url = format!("{}/api/v1/fpn/activate", endpoint.trim_end_matches('/'));

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(MOZILLA_VPN_USER_AGENT));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", access_token))
                .map_err(|e| GuardianError::Parse(e.to_string()))?,
        );

        let mut res = self
            .client
            .post(&url)
            .headers(headers.clone())
            .send()
            .await?;

        if res.status().as_u16() == 406 {
            self.solver
                .solve_and_install("https://api.accounts.firefox.com")
                .await?;
            res = self.client.post(&url).headers(headers).send().await?;
        }

        if !res.status().is_success() {
            return Err(GuardianError::Api {
                status: res.status().as_u16(),
                message: res.text().await.unwrap_or_default(),
            });
        }

        let body: serde_json::Value = res.json().await?;
        Ok(Entitlement {
            subscribed: body["subscribed"].as_bool().unwrap_or(false),
            uid: body["uid"].as_str().unwrap_or_default().to_string(),
            max_bytes: body["maxBytes"].as_i64(),
            limited_bandwidth: body["limited_bandwidth"].as_bool().unwrap_or(false),
            quota_remaining: None,
        })
    }
}

impl Default for GuardianClient {
    fn default() -> Self {
        Self::new()
    }
}
