use crate::auth::fxa_client::{AuthError, FxaClient, OAuthTokens};
use crate::auth::secret_storage::{SecretStore, StoredSecrets};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Dynamic token provider trait allowing automatic credential lookup and async refresh (H1, R-16)
pub trait TokenProvider: Send + Sync {
    fn get_access_token<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;
}

pub struct StaticTokenProvider(pub String);

impl TokenProvider for StaticTokenProvider {
    fn get_access_token<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        let tok = self.0.clone();
        Box::pin(async move { Ok(tok) })
    }
}

pub struct FxaTokenProvider {
    fxa_client: Arc<FxaClient>,
    tokens: Arc<RwLock<Option<OAuthTokens>>>,
    secret_store: Arc<SecretStore>,
}

impl FxaTokenProvider {
    pub fn new(fxa_client: Arc<FxaClient>, secret_store: Arc<SecretStore>) -> Self {
        let initial_tokens = secret_store.load().ok().flatten().map(|s| OAuthTokens {
            access_token: s.access_token.clone(),
            refresh_token: s.refresh_token.clone(),
            expires_at_epoch_seconds: s.expires_at_epoch_sec.unwrap_or(0),
        });

        Self {
            fxa_client,
            tokens: Arc::new(RwLock::new(initial_tokens)),
            secret_store,
        }
    }

    pub fn with_tokens(
        fxa_client: Arc<FxaClient>,
        secret_store: Arc<SecretStore>,
        initial_tokens: Option<OAuthTokens>,
    ) -> Self {
        Self {
            fxa_client,
            tokens: Arc::new(RwLock::new(initial_tokens)),
            secret_store,
        }
    }

    pub async fn current_tokens(&self) -> Option<OAuthTokens> {
        self.tokens.read().await.clone()
    }

    pub async fn set_tokens(&self, tokens: OAuthTokens, email: &str) -> Result<(), String> {
        let mut lock = self.tokens.write().await;
        let stored = StoredSecrets {
            email: email.to_string(),
            uid: "".to_string(),
            access_token: tokens.access_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            expires_at_epoch_sec: Some(tokens.expires_at_epoch_seconds),
        };
        let _ = self.secret_store.save(&stored);
        *lock = Some(tokens);
        Ok(())
    }

    pub async fn get_access_token_async(&self) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Fast read lock: return access token if it has >= 60 seconds validity
        {
            let lock = self.tokens.read().await;
            if let Some(ref t) = *lock {
                if t.expires_at_epoch_seconds > now + 60 {
                    return Ok(t.access_token.clone());
                }
            } else {
                return Err("Not authenticated. Please sign in with Firefox Accounts.".into());
            }
        }

        // 2. Token expired or near expiry -> acquire write lock to refresh
        let mut lock = self.tokens.write().await;
        // Double check condition under write lock
        if let Some(ref t) = *lock {
            if t.expires_at_epoch_seconds > now + 60 {
                return Ok(t.access_token.clone());
            }
        }

        let refresh_tok = match lock.as_ref().and_then(|t| t.refresh_token.clone()) {
            Some(rt) => rt,
            None => {
                return Err("No refresh token available to refresh expired session.".into());
            }
        };

        match self.fxa_client.refresh_access_token(&refresh_tok).await {
            Ok(new_tokens) => {
                let access_tok = new_tokens.access_token.clone();
                let mut stored = self
                    .secret_store
                    .load()
                    .ok()
                    .flatten()
                    .unwrap_or(StoredSecrets {
                        email: "".to_string(),
                        uid: "".to_string(),
                        access_token: new_tokens.access_token.clone(),
                        refresh_token: new_tokens.refresh_token.clone(),
                        expires_at_epoch_sec: Some(new_tokens.expires_at_epoch_seconds),
                    });
                stored.access_token = new_tokens.access_token.clone();
                stored.refresh_token = new_tokens.refresh_token.clone();
                stored.expires_at_epoch_sec = Some(new_tokens.expires_at_epoch_seconds);
                let _ = self.secret_store.save(&stored);
                *lock = Some(new_tokens);
                Ok(access_tok)
            }
            Err(AuthError::Api { status, message })
                if status == 400 || status == 401 || status == 403 =>
            {
                // Permanent auth failure (C7, R-16): session revoked on server or invalid refresh token
                *lock = None;
                let _ = self.secret_store.clear();
                Err(format!(
                    "PermanentAuthError: Refresh token rejected (HTTP {}): {}",
                    status, message
                ))
            }
            Err(e) => {
                // Transient network failure: if existing token is not completely expired, allow fallback
                if let Some(ref t) = *lock {
                    if t.expires_at_epoch_seconds > now {
                        return Ok(t.access_token.clone());
                    }
                }
                Err(format!("TransientAuthError: {:?}", e))
            }
        }
    }

    pub async fn sign_out(&self) -> Result<(), String> {
        let mut lock = self.tokens.write().await;
        if let Some(ref t) = *lock {
            let _ = self.fxa_client.revoke_token(&t.access_token).await;
            if let Some(ref rt) = t.refresh_token {
                let _ = self.fxa_client.revoke_token(rt).await;
            }
        }
        *lock = None;
        let _ = self.secret_store.clear();
        Ok(())
    }
}

impl TokenProvider for FxaTokenProvider {
    fn get_access_token<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(self.get_access_token_async())
    }
}
