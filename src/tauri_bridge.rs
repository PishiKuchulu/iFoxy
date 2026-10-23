use crate::auth::fxa_client::{AuthError, FxaClient, LoginResult};
use crate::auth::secret_storage::{SecretStore, StoredSecrets};
use crate::servers::client::ServerListClient;
use crate::servers::model::VpnCountry;
use crate::service::vpn_service::{ConnectionMode, ConnectionState, VpnService};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

pub fn load_stored_session() -> Option<StoredSecrets> {
    SecretStore::new().load().ok().flatten()
}

pub fn save_stored_session(session: &StoredSecrets) {
    let _ = SecretStore::new().save(session);
}

pub fn clear_stored_session() {
    let _ = SecretStore::new().clear();
}

pub struct AppState {
    pub vpn_service: Arc<VpnService>,
    pub fxa_client: Arc<FxaClient>,
    pub token_provider: Arc<crate::auth::token_provider::FxaTokenProvider>,
    pub server_client: Arc<ServerListClient>,
    pub logs: Arc<Mutex<Vec<String>>>,
    pub session: Arc<Mutex<Option<StoredSecrets>>>,
    pub pending_2fa: Arc<Mutex<Option<(String, String)>>>, // (session_token, email)
    pub cached_countries: Arc<Mutex<Vec<VpnCountry>>>,
}

fn format_auth_error(e: AuthError) -> String {
    match e {
        AuthError::Api { message, .. } => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&message) {
                if let Some(m) = v["message"].as_str() {
                    return m.to_string();
                }
                if let Some(m) = v["error"].as_str() {
                    return m.to_string();
                }
            }
            message
        }
        other => format!("Authentication error: {:?}", other),
    }
}

impl AppState {
    pub fn new() -> Self {
        let loaded = load_stored_session();
        let initial_logs = vec![
            "🦊 iFoxy Windows Core Initialized".to_string(),
            "Ready for full-system TUN L3 and HTTP/2 CONNECT tunneling".to_string(),
        ];

        let fxa_client = Arc::new(FxaClient::new());
        let secret_store = Arc::new(crate::auth::secret_storage::SecretStore::new());
        let token_provider = Arc::new(crate::auth::token_provider::FxaTokenProvider::new(
            fxa_client.clone(),
            secret_store,
        ));

        Self {
            vpn_service: Arc::new(VpnService::new()),
            fxa_client,
            token_provider,
            server_client: Arc::new(ServerListClient::new()),
            logs: Arc::new(Mutex::new(initial_logs)),
            session: Arc::new(Mutex::new(loaded)),
            pending_2fa: Arc::new(Mutex::new(None)),
            cached_countries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn log(&self, msg: &str) {
        tracing::info!("{}", msg);
        if let Ok(mut lock) = self.logs.lock() {
            lock.push(msg.to_string());
        }
    }

    pub async fn dispatch_action(&self, action: &str, payload: Value) -> Value {
        match action {
            "get_auth_state" => {
                let session = self.session.lock().unwrap().clone();
                match session {
                    Some(s) => json!({
                        "is_authenticated": true,
                        "email": s.email,
                        "uid": s.uid,
                    }),
                    None => json!({
                        "is_authenticated": false,
                        "email": null,
                    }),
                }
            }
            "login" => {
                let email = payload["email"]
                    .as_str()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let password = payload["password"].as_str().unwrap_or_default().to_string();

                if email.is_empty() || password.is_empty() {
                    return json!({ "success": false, "error": "Email and password are required" });
                }

                self.log(&format!(
                    "Starting Firefox Accounts authentication for {}",
                    email
                ));

                match self.fxa_client.login(&email, &password).await {
                    Ok(LoginResult::Requires2Fa { session_token }) => {
                        *self.pending_2fa.lock().unwrap() = Some((session_token, email.clone()));
                        self.log("Two-factor confirmation code sent to email");
                        json!({
                            "success": true,
                            "needs_2fa": true,
                            "email": email,
                        })
                    }
                    Ok(LoginResult::Success(tokens)) => {
                        let session = StoredSecrets {
                            email: email.clone(),
                            uid: "".to_string(),
                            access_token: tokens.access_token.clone(),
                            refresh_token: tokens.refresh_token.clone(),
                            expires_at_epoch_sec: Some(tokens.expires_at_epoch_seconds),
                        };
                        save_stored_session(&session);
                        let _ = self.token_provider.set_tokens(tokens, &email).await;
                        *self.session.lock().unwrap() = Some(session);
                        self.log(&format!("Successfully authenticated {}", email));
                        json!({
                            "success": true,
                            "needs_2fa": false,
                            "email": email,
                        })
                    }
                    Err(e) => {
                        let err_msg = format_auth_error(e);
                        self.log(&format!("Authentication failed: {}", err_msg));
                        json!({ "success": false, "error": err_msg })
                    }
                }
            }
            "verify_2fa" => {
                let code = payload["code"]
                    .as_str()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let pending = self.pending_2fa.lock().unwrap().clone();

                let (session_token, email) = match pending {
                    Some(p) => p,
                    None => {
                        return json!({ "success": false, "error": "No pending 2FA login session" })
                    }
                };

                self.log(&format!("Verifying 2FA confirmation code for {}", email));

                match self.fxa_client.verify_2fa(&session_token, &code).await {
                    Ok(tokens) => {
                        let session = StoredSecrets {
                            email: email.clone(),
                            uid: "".to_string(),
                            access_token: tokens.access_token.clone(),
                            refresh_token: tokens.refresh_token.clone(),
                            expires_at_epoch_sec: Some(tokens.expires_at_epoch_seconds),
                        };
                        save_stored_session(&session);
                        let _ = self.token_provider.set_tokens(tokens, &email).await;
                        *self.session.lock().unwrap() = Some(session);
                        *self.pending_2fa.lock().unwrap() = None;
                        self.log(&format!("2FA verified successfully for {}", email));
                        json!({ "success": true, "email": email })
                    }
                    Err(e) => {
                        let err_msg = format_auth_error(e);
                        self.log(&format!("2FA verification error: {}", err_msg));
                        json!({ "success": false, "error": err_msg })
                    }
                }
            }
            "logout" => {
                self.vpn_service.cancel();
                let _ = self.vpn_service.disconnect();
                let _ = self.token_provider.sign_out().await;
                clear_stored_session();
                *self.session.lock().unwrap() = None;
                self.log("Signed out from Firefox account, revoked server token, and cleared credentials");
                json!({ "success": true })
            }
            "fetch_server_list" => {
                match self.server_client.fetch_countries().await {
                    Ok(countries) => {
                        *self.cached_countries.lock().unwrap() = countries.clone();
                        json!({
                            "success": true,
                            "countries": countries,
                        })
                    }
                    Err(e) => {
                        // Return cached or defaults
                        let cached = self.cached_countries.lock().unwrap().clone();
                        if !cached.is_empty() {
                            json!({ "success": true, "countries": cached })
                        } else {
                            json!({ "success": false, "error": format!("{:?}", e) })
                        }
                    }
                }
            }
            "connect_vpn" => {
                // Fetch valid or refreshed access token via token_provider (H1, R-16)
                let access_token = match self.token_provider.get_access_token_async().await {
                    Ok(tok) => tok,
                    Err(e) => {
                        let err_msg = format!("Authentication error: {}. Please sign in again.", e);
                        self.log(&err_msg);
                        return json!({ "success": false, "error": err_msg });
                    }
                };

                let country_code = payload["country_code"].as_str().unwrap_or("REC");
                let city_code = payload["city_code"].as_str().unwrap_or("AUTO");

                // Get candidates
                let mut countries = self.cached_countries.lock().unwrap().clone();
                if countries.is_empty() {
                    if let Ok(fetched) = self.server_client.fetch_countries().await {
                        countries = fetched;
                        *self.cached_countries.lock().unwrap() = countries.clone();
                    }
                }

                let mut candidates = if country_code.eq_ignore_ascii_case("REC") {
                    // Try to pick Frankfurt DE or US or first available
                    let de_candidates = ServerListClient::candidates_for_country(&countries, "DE");
                    if !de_candidates.is_empty() {
                        de_candidates
                    } else if let Some(country) = countries.first() {
                        ServerListClient::candidates_for_country(&countries, &country.code)
                    } else {
                        Vec::new()
                    }
                } else if !city_code.eq_ignore_ascii_case("AUTO") {
                    ServerListClient::candidates_for_city(&countries, country_code, city_code)
                } else {
                    ServerListClient::candidates_for_country(&countries, country_code)
                };

                if candidates.is_empty() {
                    let err_msg = format!(
                        "No proxy servers available for country '{}', city '{}'. Refusing to invent fallback hosts.",
                        country_code, city_code
                    );
                    self.log(&err_msg);
                    return json!({ "success": false, "error": err_msg });
                }

                // Wire M3: Latency probing and failover ranking before connection
                self.log(&format!(
                    "Probing latency across {} candidate server(s)...",
                    candidates.len()
                ));
                ServerListClient::probe_and_rank_candidates(
                    &mut candidates,
                    std::time::Duration::from_millis(1500),
                )
                .await;

                let candidate = candidates.remove(0);
                if let Some(lat) = candidate.latency_ms {
                    self.log(&format!(
                        "Selected fastest candidate: {} ({}:{}) with latency {}ms",
                        candidate.country_name, candidate.host, candidate.port, lat
                    ));
                }

                // Default to ProxyOnly as safe default until Full mode verified on system
                let mode = match payload.get("mode").and_then(|v| v.as_str()) {
                    Some("full") => ConnectionMode::Full,
                    _ => ConnectionMode::ProxyOnly,
                };

                self.log(&format!(
                    "Connecting to {} ({}:{}) in {:?} mode",
                    candidate.country_name, candidate.host, candidate.port, mode
                ));

                match self
                    .vpn_service
                    .start_connect(candidate, &access_token, mode)
                    .await
                {
                    Ok(_) => {
                        self.log("Tunnel connection established successfully!");
                        json!({ "success": true })
                    }
                    Err(e) => {
                        let err_msg = match e {
                            crate::service::vpn_service::ServiceError::Vpn(msg) => msg,
                            _ => format!("{}", e),
                        };
                        self.log(&format!("Connection error: {}", err_msg));
                        json!({ "success": false, "error": err_msg })
                    }
                }
            }
            "disconnect_vpn" => {
                self.log("Disconnecting VPN tunnel...");
                self.vpn_service.cancel();
                let _ = self.vpn_service.disconnect();
                self.log("VPN Disconnected cleanly.");
                json!({ "success": true })
            }
            "get_vpn_status" => {
                let vpn_state = self.vpn_service.get_state();
                let (bytes_sent, bytes_received) = self.vpn_service.get_traffic_metrics().await;
                let status = match vpn_state {
                    ConnectionState::Connected { target, mode } => json!({
                        "state": "connected",
                        "mode": format!("{:?}", mode).to_lowercase(),
                        "current_country": target.country_name,
                        "current_city": target.city_name.unwrap_or(target.city_code),
                        "bytes_sent": bytes_sent,
                        "bytes_received": bytes_received,
                    }),
                    ConnectionState::Connecting => json!({
                        "state": "connecting",
                        "bytes_sent": bytes_sent,
                        "bytes_received": bytes_received,
                    }),
                    ConnectionState::Reconnecting { attempt, target } => json!({
                        "state": "reconnecting",
                        "attempt": attempt,
                        "current_country": target.country_name,
                        "current_city": target.city_name.unwrap_or(target.city_code),
                        "bytes_sent": bytes_sent,
                        "bytes_received": bytes_received,
                    }),
                    ConnectionState::Disconnecting => json!({
                        "state": "disconnecting",
                        "bytes_sent": bytes_sent,
                        "bytes_received": bytes_received,
                    }),
                    ConnectionState::Failed(msg) => json!({
                        "state": "failed",
                        "error": msg,
                        "bytes_sent": bytes_sent,
                        "bytes_received": bytes_received,
                    }),
                    ConnectionState::Disconnected => json!({
                        "state": "disconnected",
                        "bytes_sent": bytes_sent,
                        "bytes_received": bytes_received,
                    }),
                };
                status
            }
            "get_entitlement" => {
                let access_token = match self.token_provider.get_access_token_async().await {
                    Ok(t) => t,
                    Err(e) => return json!({ "success": false, "error": e }),
                };
                match self
                    .vpn_service
                    .guardian
                    .fetch_user_info(
                        crate::guardian::client::GUARDIAN_ENDPOINT_DEFAULT,
                        &access_token,
                    )
                    .await
                {
                    Ok(ent) => json!({
                        "success": true,
                        "subscribed": ent.subscribed,
                        "quota_remaining": ent.quota_remaining,
                        "max_bytes": ent.max_bytes,
                    }),
                    Err(e) => json!({ "success": false, "error": format!("{:?}", e) }),
                }
            }
            "get_logs" => {
                let logs = self.logs.lock().unwrap().clone();
                json!({ "logs": logs })
            }
            _ => json!({ "success": false, "error": "Unknown action" }),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// Embedded UI Assets
pub const INDEX_HTML: &str = include_str!("../ui/index.html");
pub const STYLE_CSS: &str = include_str!("../ui/style.css");
pub const APP_JS: &str = include_str!("../ui/app.js");
pub const IFOXY_LOGO_PNG: &[u8] = include_bytes!("../ui/assets/ifoxy_logo.png");
pub const IFOXY_SPLASH_PNG: &[u8] = include_bytes!("../ui/assets/ifoxy_splash.png");
pub const IFOXY_BANNER_PNG: &[u8] = include_bytes!("../ui/assets/ifoxy_banner.png");
pub const IFOXY_WORDMARK_PNG: &[u8] = include_bytes!("../ui/assets/ifoxy_wordmark.png");

pub async fn bind_ui_server(preferred_port: u16) -> Result<(TcpListener, u16), std::io::Error> {
    if let Ok(listener) = crate::vpn::local_proxy::bind_listener(&format!("127.0.0.1:{}", preferred_port)).await {
        let port = listener.local_addr()?.port();
        return Ok((listener, port));
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}
