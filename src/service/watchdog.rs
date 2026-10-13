use crate::guardian::client::GuardianClient;
use crate::tunnel::h2_session::H2UpstreamSession;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

pub const PROXY_PASS_RENEWAL_FRACTION: f64 = 0.5;
pub const PROXY_PASS_RENEWAL_SAFETY_MARGIN_SECONDS: u64 = 30;
pub const PROXY_PASS_RENEWAL_FLOOR_SECONDS: u64 = 15;
pub const PROXY_PASS_RENEWAL_CEILING_SECONDS: u64 = 1800; // 30 mins
pub const PROXY_PASS_RENEWAL_FALLBACK_SECONDS: u64 = 240; // 4 mins

pub use crate::auth::token_provider::{StaticTokenProvider, TokenProvider};

pub fn calculate_renewal_delay_seconds(
    now_epoch_seconds: u64,
    expires_at_epoch_seconds: Option<u64>,
) -> u64 {
    let expires_at = match expires_at_epoch_seconds {
        Some(exp) => exp,
        None => return PROXY_PASS_RENEWAL_FALLBACK_SECONDS,
    };

    let remaining = expires_at.saturating_sub(now_epoch_seconds);
    if remaining == 0 {
        return PROXY_PASS_RENEWAL_FLOOR_SECONDS;
    }

    let at_half_life = (remaining as f64 * PROXY_PASS_RENEWAL_FRACTION) as u64;
    let before_expiry = remaining.saturating_sub(PROXY_PASS_RENEWAL_SAFETY_MARGIN_SECONDS);

    std::cmp::min(at_half_life, before_expiry).clamp(
        PROXY_PASS_RENEWAL_FLOOR_SECONDS,
        PROXY_PASS_RENEWAL_CEILING_SECONDS,
    )
}

pub struct TokenRenewalWorker {
    running: Arc<AtomicBool>,
}

impl TokenRenewalWorker {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start_with_provider(
        &self,
        guardian: Arc<GuardianClient>,
        guardian_endpoint: String,
        token_provider: Arc<dyn TokenProvider>,
        session: Arc<H2UpstreamSession>,
        initial_expires_at: Option<u64>,
    ) -> JoinHandle<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            let mut current_expires_at = initial_expires_at;

            while running.load(Ordering::SeqCst) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let delay_secs = calculate_renewal_delay_seconds(now, current_expires_at);
                tracing::info!(
                    "Token renewal watchdog scheduled in {} seconds (expires_at={:?})",
                    delay_secs,
                    current_expires_at
                );

                tokio::time::sleep(Duration::from_secs(delay_secs)).await;

                if !running.load(Ordering::SeqCst) {
                    break;
                }

                let access_token = match token_provider.get_access_token().await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!("Token renewal provider failed: {:?}", e);
                        current_expires_at = Some(now + PROXY_PASS_RENEWAL_FLOOR_SECONDS + 15);
                        continue;
                    }
                };

                tracing::info!("Refreshing Mozilla Guardian proxy pass token...");
                match guardian
                    .fetch_proxy_pass(&guardian_endpoint, &access_token)
                    .await
                {
                    Ok(pass) => {
                        session.update_token(&pass.token);
                        current_expires_at = pass.expires_at_epoch_seconds;
                        tracing::info!(
                            "Proxy pass token successfully refreshed and applied! New expiry: {:?}",
                            current_expires_at
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Failed to renew proxy pass token: {:?}", e);
                        // Retry sooner on error
                        current_expires_at = Some(now + PROXY_PASS_RENEWAL_FLOOR_SECONDS + 15);
                    }
                }
            }
            tracing::info!("Token renewal watchdog terminated");
        })
    }

    pub fn start(
        &self,
        guardian: Arc<GuardianClient>,
        guardian_endpoint: String,
        access_token: String,
        session: Arc<H2UpstreamSession>,
        initial_expires_at: Option<u64>,
    ) -> JoinHandle<()> {
        self.start_with_provider(
            guardian,
            guardian_endpoint,
            Arc::new(StaticTokenProvider(access_token)),
            session,
            initial_expires_at,
        )
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Default for TokenRenewalWorker {
    fn default() -> Self {
        Self::new()
    }
}
