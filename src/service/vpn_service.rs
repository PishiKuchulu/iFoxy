use crate::guardian::client::GuardianClient;
use crate::servers::model::ProxyCandidate;
use crate::service::state_machine::{ServiceCommand, StateMachineActor};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionMode {
    Full,
    ProxyOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected {
        mode: ConnectionMode,
        target: ProxyCandidate,
    },
    Reconnecting {
        attempt: u32,
        target: ProxyCandidate,
    },
    Disconnecting,
    Failed(String),
}

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Already connecting or connected")]
    AlreadyActive,
    #[error("Not connected")]
    NotConnected,
    #[error("DNS resolution failed for {0}")]
    DnsResolution(String),
    #[error("VPN error: {0}")]
    Vpn(String),
}

pub struct VpnService {
    cmd_tx: mpsc::Sender<ServiceCommand>,
    state_rx: watch::Receiver<ConnectionState>,
    pub guardian: Arc<GuardianClient>,
}

impl VpnService {
    pub fn new() -> Self {
        let guardian = Arc::new(GuardianClient::new());
        let (cmd_tx, state_rx) = StateMachineActor::spawn(guardian.clone());
        Self {
            cmd_tx,
            state_rx,
            guardian,
        }
    }

    pub fn get_state(&self) -> ConnectionState {
        self.state_rx.borrow().clone()
    }

    pub fn subscribe_state(&self) -> watch::Receiver<ConnectionState> {
        self.state_rx.clone()
    }

    pub async fn start_connect(
        &self,
        candidate: ProxyCandidate,
        access_token: &str,
        mode: ConnectionMode,
    ) -> Result<(), ServiceError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(ServiceCommand::Connect {
                candidate,
                access_token: access_token.to_string(),
                mode,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ServiceError::Vpn("Actor channel closed".into()))?;

        reply_rx
            .await
            .map_err(|_| ServiceError::Vpn("Connect response dropped".into()))?
    }

    pub fn cancel(&self) {
        let _ = self.cmd_tx.try_send(ServiceCommand::Cancel);
    }

    pub fn disconnect(&self) -> Result<(), ServiceError> {
        let (reply_tx, _reply_rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .try_send(ServiceCommand::Disconnect { reply: reply_tx });
        Ok(())
    }

    pub async fn disconnect_async(&self) -> Result<(), ServiceError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(ServiceCommand::Disconnect { reply: reply_tx })
            .await;
        let _ = reply_rx.await;
        Ok(())
    }

    pub async fn get_traffic_metrics(&self) -> (u64, u64) {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(ServiceCommand::GetMetrics { reply: reply_tx })
            .await
            .is_ok()
        {
            reply_rx.await.unwrap_or((0, 0))
        } else {
            (0, 0)
        }
    }

    pub async fn notify_network_changed(&self) {
        let _ = self.cmd_tx.send(ServiceCommand::NetworkChanged).await;
    }

    pub async fn notify_token_refreshed(&self, new_token: &str) {
        let _ = self
            .cmd_tx
            .send(ServiceCommand::TokenRefreshed {
                new_token: new_token.to_string(),
            })
            .await;
    }
}

impl Default for VpnService {
    fn default() -> Self {
        Self::new()
    }
}
