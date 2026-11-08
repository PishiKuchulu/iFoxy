use crate::auth::fxa_client::{AuthError, FxaClient, LoginResult};
use crate::auth::secret_storage::{SecretStore, StoredSecrets};
use crate::servers::client::ServerListClient;
use crate::servers::model::VpnCountry;
use crate::service::vpn_service::{ConnectionMode, ConnectionState, VpnService};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use zeroize::Zeroize;

pub fn load_stored_session() -> Option<StoredSecrets> {
    SecretStore::new().load().ok().flatten()
}

pub fn save_stored_session(session: &StoredSecrets) {
    let _ = SecretStore::new().save(session);
}

pub fn clear_stored_session() {
    let _ = SecretStore::new().clear();
}

/// A pending two-factor login: the FxA session token plus the
/// bookkeeping the old bare tuple lacked (wave-3 review, M-6) — an
/// expiry and an attempt cap, so a pending session cannot be probed
/// forever while the app runs.
pub struct PendingTwoFactor {
    pub session_token: String,
    pub email: String,
    pub started_at: std::time::Instant,
    pub attempts: u32,
}

/// How long a pending 2FA login stays usable.
pub const PENDING_2FA_TTL: std::time::Duration = std::time::Duration::from_secs(600);
/// Failed verification attempts before the pending session is dropped.
pub const MAX_2FA_ATTEMPTS: u32 = 5;

pub struct AppState {
    pub vpn_service: Arc<VpnService>,
    pub fxa_client: Arc<FxaClient>,
    pub token_provider: Arc<crate::auth::token_provider::FxaTokenProvider>,
    pub server_client: Arc<ServerListClient>,
    pub logs: Arc<Mutex<Vec<String>>>,
    pub session: Arc<Mutex<Option<StoredSecrets>>>,
    pub pending_2fa: Arc<Mutex<Option<PendingTwoFactor>>>,
    pub cached_countries: Arc<Mutex<Vec<VpnCountry>>>,
}

/// Replace anything shaped like an email address with a masked form
/// (`f***@example.com`) for log output.
fn mask_emails(msg: &str) -> String {
    msg.split(' ')
        .map(|word| {
            if let Some((local, domain)) = word.split_once('@') {
                if !local.is_empty() && domain.contains('.') {
                    let first = local.chars().next().unwrap_or('*');
                    return format!("{}***@{}", first, domain);
                }
            }
            word.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ")
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
        // Mask email addresses and cap the buffer: log lines used to
        // embed the account email in clear text and the Vec grew for
        // the whole process lifetime (external review, S9). The logs
        // are user-exportable, so the masked form is what gets stored
        // and traced alike.
        let masked = mask_emails(msg);
        tracing::info!("{}", masked);
        if let Ok(mut lock) = self.logs.lock() {
            lock.push(masked);
            const MAX_LOG_LINES: usize = 500;
            if lock.len() > MAX_LOG_LINES {
                let excess = lock.len() - MAX_LOG_LINES;
                lock.drain(..excess);
            }
        }
    }

    pub async fn dispatch_action(&self, action: &str, payload: Value) -> Value {
        match action {
            "get_auth_state" => {
                // The token provider is the credential source of truth:
                // when a permanent refresh failure clears its tokens and
                // the stored session, this view must not keep reporting
                // the stale AppState.session as authenticated (external
                // review, S7). Sync the cached session with it.
                if self.token_provider.current_tokens().await.is_none() {
                    *self.session.lock().unwrap_or_else(|p| p.into_inner()) = None;
                    return json!({
                        "is_authenticated": false,
                        "email": null,
                    });
                }
                let session = self.session.lock().unwrap_or_else(|p| p.into_inner()).clone();
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
                let mut password = payload["password"].as_str().unwrap_or_default().to_string();

                if email.is_empty() || password.is_empty() {
                    return json!({ "success": false, "error": "Email and password are required" });
                }

                self.log(&format!(
                    "Starting Firefox Accounts authentication for {}",
                    email
                ));

                let login_result = self.fxa_client.login(&email, &password).await;
                password.zeroize();
                match login_result {
                    Ok(LoginResult::Requires2Fa { session_token }) => {
                        *self.pending_2fa.lock().unwrap_or_else(|p| p.into_inner()) =
                            Some(PendingTwoFactor {
                                session_token,
                                email: email.clone(),
                                started_at: std::time::Instant::now(),
                                attempts: 0,
                            });
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
                        *self.session.lock().unwrap_or_else(|p| p.into_inner()) = Some(session);
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
                let pending = {
                    let mut lock = self.pending_2fa.lock().unwrap_or_else(|p| p.into_inner());
                    match lock.take() {
                        Some(p) if p.started_at.elapsed() > PENDING_2FA_TTL => {
                            // Expired: drop it (zeroized) and make the
                            // user sign in again (M-6).
                            let mut p = p;
                            p.session_token.zeroize();
                            None
                        }
                        Some(p) => {
                            let snapshot = PendingTwoFactor {
                                session_token: p.session_token.clone(),
                                email: p.email.clone(),
                                started_at: p.started_at,
                                attempts: p.attempts,
                            };
                            *lock = Some(p);
                            Some(snapshot)
                        }
                        None => None,
                    }
                };

                let (session_token, email) = match pending {
                    Some(p) => (p.session_token, p.email),
                    None => {
                        return json!({ "success": false, "error": "No pending 2FA login session (it may have expired); please sign in again" })
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
                        *self.session.lock().unwrap_or_else(|p| p.into_inner()) = Some(session);
                        if let Some(mut p) = self
                            .pending_2fa
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .take()
                        {
                            p.session_token.zeroize();
                        }
                        self.log(&format!("2FA verified successfully for {}", email));
                        json!({ "success": true, "email": email })
                    }
                    Err(e) => {
                        let err_msg = format_auth_error(e);
                        // Attempt cap (M-6): a failed code consumes one
                        // of MAX_2FA_ATTEMPTS tries; at the cap the
                        // pending session is dropped (zeroized).
                        let exhausted = {
                            let mut lock =
                                self.pending_2fa.lock().unwrap_or_else(|p| p.into_inner());
                            match lock.as_mut() {
                                Some(p) => {
                                    p.attempts += 1;
                                    if p.attempts >= MAX_2FA_ATTEMPTS {
                                        if let Some(mut dropped) = lock.take() {
                                            dropped.session_token.zeroize();
                                        }
                                        true
                                    } else {
                                        false
                                    }
                                }
                                None => false,
                            }
                        };
                        if exhausted {
                            self.log("2FA attempts exhausted; pending login dropped");
                            json!({ "success": false, "error": "Too many incorrect codes. Please sign in again." })
                        } else {
                            self.log(&format!("2FA verification error: {}", err_msg));
                            json!({ "success": false, "error": err_msg })
                        }
                    }
                }
            }
            "logout" => {
                self.vpn_service.cancel();
                let _ = self.vpn_service.disconnect();
                let revoked = self
                    .token_provider
                    .sign_out()
                    .await
                    .unwrap_or(false);
                clear_stored_session();
                *self.session.lock().unwrap_or_else(|p| p.into_inner()) = None;
                if revoked {
                    self.log("Signed out from Firefox account, revoked server token, and cleared credentials");
                } else {
                    self.log("Signed out from Firefox account and cleared local credentials; server token revocation did not complete");
                }
                json!({ "success": true })
            }
            "fetch_server_list" => {
                match self.server_client.fetch_countries().await {
                    Ok(countries) => {
                        *self.cached_countries.lock().unwrap_or_else(|p| p.into_inner()) = countries.clone();
                        json!({
                            "success": true,
                            "countries": countries,
                        })
                    }
                    Err(e) => {
                        // Return cached or defaults
                        let cached = self.cached_countries.lock().unwrap_or_else(|p| p.into_inner()).clone();
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
                let mut countries = self.cached_countries.lock().unwrap_or_else(|p| p.into_inner()).clone();
                if countries.is_empty() {
                    if let Ok(fetched) = self.server_client.fetch_countries().await {
                        countries = fetched;
                        *self.cached_countries.lock().unwrap_or_else(|p| p.into_inner()) = countries.clone();
                    }
                }

                let mut candidates = if country_code.eq_ignore_ascii_case("REC") {
                    // "Recommended" = fastest edge anywhere: gather every
                    // country's candidates and let latency probing rank
                    // them (wave-3 review, H-4 — this used to hardcode
                    // Germany and never fall back).
                    let mut all = Vec::new();
                    for country in &countries {
                        all.extend(ServerListClient::candidates_for_country(
                            &countries,
                            &country.code,
                        ));
                    }
                    all
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

                let mut ranked =
                    ServerListClient::select_failover_candidates(candidates).into_iter();
                let candidate = ranked.next().expect("candidates checked non-empty above");
                let failover_candidates: Vec<_> = ranked.take(7).collect();
                if !failover_candidates.is_empty() {
                    self.log(&format!(
                        "Failover: {} alternate edge(s) queued for reconnect",
                        failover_candidates.len()
                    ));
                }
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

                let chosen_latency_ms = candidate.latency_ms;

                match self
                    .vpn_service
                    .start_connect(
                        candidate,
                        &access_token,
                        mode,
                        Some(self.token_provider.clone()),
                        failover_candidates,
                    )
                    .await
                {
                    Ok(_) => {
                        self.log("Tunnel connection established successfully!");
                        match chosen_latency_ms {
                            Some(lat) => json!({ "success": true, "latency_ms": lat }),
                            None => json!({ "success": true }),
                        }
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
                // Only claim a clean disconnect when the Disconnect
                // command actually reached the actor (M-13).
                match self.vpn_service.disconnect() {
                    Ok(()) => {
                        self.log("VPN Disconnected cleanly.");
                        json!({ "success": true })
                    }
                    Err(e) => {
                        let err_msg = format!("Disconnect failed: {}", e);
                        self.log(&err_msg);
                        json!({ "success": false, "error": err_msg })
                    }
                }
            }
            "get_vpn_status" => {
                let vpn_state = self.vpn_service.get_state();
                let (bytes_sent, bytes_received) = self.vpn_service.get_traffic_metrics().await;
                match vpn_state {
                    ConnectionState::Connected { target, mode } => json!({
                        "state": "connected",
                        "mode": match mode {
                            ConnectionMode::Full => "full",
                            ConnectionMode::ProxyOnly => "proxy_only",
                        },
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
                }
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
                let logs = self.logs.lock().unwrap_or_else(|p| p.into_inner()).clone();
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
    // The fixed port was taken (another process, or a leftover
    // instance): fall back to a random port, but say so loudly — a
    // silent fallback hides a possible local squatter (M-3). The
    // control API's random token remains the actual auth boundary.
    tracing::warn!(
        "UI port {} unavailable; falling back to a random port",
        preferred_port
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}
