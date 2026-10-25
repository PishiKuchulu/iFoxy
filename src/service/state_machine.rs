use crate::auth::token_provider::TokenProvider;
use crate::guardian::client::GuardianClient;
use crate::servers::model::ProxyCandidate;
use crate::service::vpn_service::{ConnectionMode, ConnectionState, ServiceError};
use crate::service::watchdog::TokenRenewalWorker;
use crate::tunnel::h2_session::H2UpstreamSession;
use crate::vpn::local_proxy::{LocalProxyServer, DEFAULT_LOCAL_PROXY_PORT};
#[cfg(target_os = "linux")]
use crate::vpn::linux_tun::LinuxTunDevice;
use crate::vpn::packet_pump::{PacketPump, TunDeviceOps};
use crate::vpn::routing::{RouteGuard, RouteManager};
use crate::vpn::system_proxy::SystemProxyGuard;
use crate::vpn::wintun_adapter::DEFAULT_WINTUN_IP;
#[cfg(windows)]
use crate::vpn::wintun_adapter::{WintunDevice, DEFAULT_ADAPTER_NAME};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub enum SupervisionEvent {
    H2GoAway(u32),
    ConnectionDropped,
    PingFailed,
    /// The physical route to the edge (gateway or interface) changed, e.g.
    /// Wi-Fi roamed or Ethernet was unplugged. Produced by the polling
    /// watcher started in `perform_connect_task` (S-5: the actor handled
    /// network changes but nothing ever produced the event).
    NetworkChanged,
}

/// Create the OS tunnel device for Full mode (Wintun on Windows, TUN on
/// Linux), returned behind the pump's device trait.
fn create_tun_device() -> Result<Arc<dyn TunDeviceOps>, ServiceError> {
    #[cfg(windows)]
    {
        let device = WintunDevice::create_or_open(DEFAULT_ADAPTER_NAME, DEFAULT_WINTUN_IP)
            .map_err(|e| ServiceError::Vpn(format!("Wintun error: {:?}", e)))?;
        Ok(Arc::new(device))
    }
    #[cfg(target_os = "linux")]
    {
        let device = LinuxTunDevice::create_or_open(DEFAULT_WINTUN_IP)
            .map_err(|e| ServiceError::Vpn(format!("TUN error: {:?}", e)))?;
        Ok(Arc::new(device))
    }
}

pub enum ServiceCommand {
    Connect {
        candidate: ProxyCandidate,
        access_token: String,
        mode: ConnectionMode,
        /// Live credential source for the token-renewal worker. When
        /// present, renewal fetches a fresh (possibly refreshed) access
        /// token from the provider on every cycle instead of re-sending
        /// the connect-time token forever (external review, P2): a
        /// long-lived session used to die at renewal time once the
        /// connect-time token expired, and `TokenRefreshed` only updated
        /// the H2 session, never the renewal worker. `None` (tests, or
        /// callers without a provider) keeps the old static-token
        /// behaviour.
        token_provider: Option<Arc<dyn TokenProvider>>,
        reply: oneshot::Sender<Result<(), ServiceError>>,
    },
    Cancel,
    Disconnect {
        reply: oneshot::Sender<()>,
    },
    NetworkChanged,
    TokenRefreshed {
        new_token: String,
    },
    Supervision(SupervisionEvent),
    GetMetrics {
        reply: oneshot::Sender<(u64, u64)>,
    },
    /// Sent by a reconnect attempt that produced a brand new, fully
    /// established SessionContext. The actor installs it directly instead
    /// of routing it back through `Connect` (which would be rejected while
    /// the state is `Reconnecting`, leaving the app stuck forever — S-2 in
    /// the round-3 review).
    ReconnectCompleted {
        session: Box<SessionContext>,
    },
    /// Sent by the reconnect task when all attempts are exhausted in
    /// Full mode: the carried kill switch is handed to the actor for
    /// retention instead of being dropped. Dropping it (the old
    /// behavior) removed the filters and left the machine fail-open on
    /// direct internet in the Failed state (external review, H3). The
    /// actor releases it on Disconnect/Cancel or disarms it when a new
    /// session's own kill switch supersedes it.
    RetainKillSwitch {
        guard: Box<crate::vpn::killswitch::KillSwitchGuard>,
    },
}

// Active task tracker to ensure zero task leaks (C5)
#[derive(Default)]
pub struct TaskTracker {
    pub active_count: Arc<AtomicUsize>,
    handles: Vec<JoinHandle<()>>,
}

impl TaskTracker {
    pub fn new() -> Self {
        Self {
            active_count: Arc::new(AtomicUsize::new(0)),
            handles: Vec::new(),
        }
    }

    pub fn spawn<F>(&mut self, future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let counter = self.active_count.clone();
        counter.fetch_add(1, Ordering::SeqCst);
        let handle = tokio::spawn(async move {
            future.await;
            counter.fetch_sub(1, Ordering::SeqCst);
        });
        self.handles.push(handle);
    }

    pub fn track(&mut self, handle: tokio::task::JoinHandle<()>) {
        let counter = self.active_count.clone();
        counter.fetch_add(1, Ordering::SeqCst);
        self.handles.push(handle);
    }

    pub async fn abort_and_join_all(&mut self) {
        for h in self.handles.drain(..) {
            h.abort();
            let _ = h.await;
        }
        self.active_count.store(0, Ordering::SeqCst);
    }
}

// Without this, a `perform_connect_task` call that returns early via `?`
// after partially starting resources (proxy/pump/renewal already tracked)
// used to leak those tasks running detached forever, because dropping a
// `Vec<JoinHandle<_>>` does not cancel the tasks it points at (S-8 in the
// round-3 review: "tracked tasks keep running" after an early failure).
impl Drop for TaskTracker {
    fn drop(&mut self) {
        for h in &self.handles {
            h.abort();
        }
    }
}

pub struct SessionContext {
    pub candidate: ProxyCandidate,
    pub access_token: String,
    pub mode: ConnectionMode,
    pub cancel_token: CancellationToken,
    pub tracker: TaskTracker,
    pub h2_session: Arc<H2UpstreamSession>,
    pub renewal_worker: TokenRenewalWorker,
    pub packet_pump: Option<PacketPump>,
    pub local_proxy: Option<LocalProxyServer>,
    pub system_proxy_guard: Option<SystemProxyGuard>,
    pub route_guard: Option<RouteGuard>,
    pub killswitch_guard: Option<crate::vpn::killswitch::KillSwitchGuard>,
}

pub struct StateMachineActor {
    cmd_tx: mpsc::Sender<ServiceCommand>,
    cmd_rx: mpsc::Receiver<ServiceCommand>,
    state_tx: watch::Sender<ConnectionState>,
    guardian: Arc<GuardianClient>,
    active_session: Option<SessionContext>,
    edge_resolver: crate::vpn::edge_resolver::EdgeResolver,
    connecting_cancel: Option<CancellationToken>,
    connecting_handle: Option<JoinHandle<Result<SessionContext, ServiceError>>>,
    connecting_reply: Option<oneshot::Sender<Result<(), ServiceError>>>,
    reconnecting_cancel: Option<CancellationToken>,
    reconnecting_handle: Option<JoinHandle<()>>,
    custom_roots: Option<rustls::RootCertStore>,
    /// Credential source handed in by the last Connect command, kept so
    /// reconnect attempts (which re-run `perform_connect_task`) renew
    /// with fresh tokens too. Cleared on Disconnect.
    token_provider: Option<Arc<dyn TokenProvider>>,
    /// Kill switch retained after a Full-mode reconnect exhaustion
    /// (see ServiceCommand::RetainKillSwitch): traffic stays blocked
    /// in the Failed state until the user disconnects or reconnects.
    retained_killswitch: Option<crate::vpn::killswitch::KillSwitchGuard>,
}

impl StateMachineActor {
    pub fn spawn(
        guardian: Arc<GuardianClient>,
    ) -> (
        mpsc::Sender<ServiceCommand>,
        watch::Receiver<ConnectionState>,
    ) {
        Self::spawn_with_roots(guardian, None)
    }

    pub fn spawn_with_roots(
        guardian: Arc<GuardianClient>,
        custom_roots: Option<rustls::RootCertStore>,
    ) -> (
        mpsc::Sender<ServiceCommand>,
        watch::Receiver<ConnectionState>,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (state_tx, state_rx) = watch::channel(ConnectionState::Disconnected);

        let mut actor = Self {
            cmd_tx: cmd_tx.clone(),
            cmd_rx,
            state_tx,
            guardian,
            active_session: None,
            edge_resolver: crate::vpn::edge_resolver::EdgeResolver::new(),
            connecting_cancel: None,
            connecting_handle: None,
            connecting_reply: None,
            reconnecting_cancel: None,
            reconnecting_handle: None,
            custom_roots,
            token_provider: None,
            retained_killswitch: None,
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                actor.run().await;
            });
        } else {
            std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(async move {
                        actor.run().await;
                    });
                }
            });
        }

        (cmd_tx, state_rx)
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                cmd_opt = self.cmd_rx.recv() => {
                    match cmd_opt {
                        Some(cmd) => self.handle_command(cmd).await,
                        None => break,
                    }
                }

                connect_res = async {
                    if let Some(h) = &mut self.connecting_handle {
                        h.await
                    } else {
                        std::future::pending().await
                    }
                }, if self.connecting_handle.is_some() => {
                    self.handle_connecting_completed(connect_res).await;
                }

                reconnect_res = async {
                    if let Some(h) = &mut self.reconnecting_handle {
                        h.await
                    } else {
                        std::future::pending().await
                    }
                }, if self.reconnecting_handle.is_some() => {
                    self.reconnecting_handle = None;
                    self.reconnecting_cancel = None;
                    let _ = reconnect_res;
                }
            }
        }
    }

    async fn handle_command(&mut self, cmd: ServiceCommand) {
        match cmd {
            ServiceCommand::Connect {
                candidate,
                access_token,
                mode,
                token_provider,
                reply,
            } => {
                // Remember the provider for reconnect attempts, which
                // re-run perform_connect_task from handle_supervision.
                self.token_provider = token_provider.clone();
                let current = self.state_tx.borrow().clone();
                if current == ConnectionState::Connecting
                    || matches!(current, ConnectionState::Connected { .. })
                    || matches!(current, ConnectionState::Reconnecting { .. })
                {
                    let _ = reply.send(Err(ServiceError::AlreadyActive));
                    return;
                }

                let cancel_token = CancellationToken::new();
                let cancel_clone = cancel_token.clone();
                let guardian = self.guardian.clone();
                let cmd_tx = self.cmd_tx.clone();

                let (sup_tx, mut sup_rx) = mpsc::channel::<SupervisionEvent>(16);
                let forwarder_handle = tokio::spawn(async move {
                    while let Some(evt) = sup_rx.recv().await {
                        let _ = cmd_tx.send(ServiceCommand::Supervision(evt)).await;
                    }
                });

                let cand_clone = candidate.clone();
                let token_clone = access_token.clone();
                let roots_clone = self.custom_roots.clone();

                let handle = tokio::spawn(async move {
                    Self::perform_connect_task(
                        guardian,
                        cand_clone,
                        token_clone,
                        token_provider,
                        mode,
                        cancel_clone,
                        sup_tx,
                        forwarder_handle,
                        roots_clone,
                        None,
                    )
                    .await
                });

                self.connecting_cancel = Some(cancel_token);
                self.connecting_handle = Some(handle);
                self.connecting_reply = Some(reply);
                let _ = self.state_tx.send(ConnectionState::Connecting);
            }

            ServiceCommand::Cancel => {
                self.abort_in_flight_operations().await;
                self.perform_disconnect().await;
                let _ = self.state_tx.send(ConnectionState::Disconnected);
            }

            ServiceCommand::Disconnect { reply } => {
                let _ = self.state_tx.send(ConnectionState::Disconnecting);
                self.token_provider = None;
                self.abort_in_flight_operations().await;
                self.perform_disconnect().await;
                let _ = self.state_tx.send(ConnectionState::Disconnected);
                let _ = reply.send(());
            }

            ServiceCommand::NetworkChanged => {
                tracing::info!("Network changed event received in state machine");
                if let Some(session) = &mut self.active_session {
                    if session.mode == ConnectionMode::Full {
                        tracing::info!(
                            "Network changed: re-applying physical gateway and bypass route"
                        );
                        if let Some(guard) = &mut session.route_guard {
                            if let Ok((new_gw, new_if_idx)) =
                                crate::vpn::routing::detect_default_gateway_and_interface()
                            {
                                let _ = guard.reapply_edge_bypass(new_gw, new_if_idx);
                            }
                        }
                    }
                }
            }

            ServiceCommand::TokenRefreshed { new_token } => {
                if let Some(session) = &mut self.active_session {
                    session.access_token = new_token.clone();
                    session.h2_session.update_token(&new_token);
                    tracing::info!("H2 session token refreshed in active session");
                }
            }

            ServiceCommand::Supervision(event) => {
                self.handle_supervision(event).await;
            }

            ServiceCommand::ReconnectCompleted { session } => {
                // A reconnect attempt succeeded while we were in the
                // `Reconnecting` state. Install it directly (S-2): the old
                // `Connect`-resend approach was rejected by the guard above
                // and left the app stuck in `Reconnecting` forever.
                self.reconnecting_handle = None;
                self.reconnecting_cancel = None;
                let mode = session.mode;
                let target = session.candidate.clone();
                self.active_session = Some(*session);
                // The new session's own kill switch supersedes any
                // retained one; disarm (do NOT clean) so the retained
                // guard's teardown cannot remove the new protection.
                if let Some(mut retained) = self.retained_killswitch.take() {
                    retained.disarm();
                }
                let _ = self
                    .state_tx
                    .send(ConnectionState::Connected { mode, target });
            }

            ServiceCommand::RetainKillSwitch { guard } => {
                if let Some(mut old) = self.retained_killswitch.take() {
                    old.disarm();
                }
                self.retained_killswitch = Some(*guard);
                tracing::warn!(
                    "Kill switch retained after reconnect exhaustion: traffic stays blocked until disconnect or a successful reconnect"
                );
            }

            ServiceCommand::GetMetrics { reply } => {
                let metrics = if let Some(session) = &self.active_session {
                    session.h2_session.get_metrics()
                } else {
                    (0, 0)
                };
                let _ = reply.send(metrics);
            }
        }
    }

    async fn handle_connecting_completed(
        &mut self,
        res: Result<Result<SessionContext, ServiceError>, tokio::task::JoinError>,
    ) {
        self.connecting_handle = None;
        self.connecting_cancel = None;
        let reply = self.connecting_reply.take();

        match res {
            Ok(Ok(session)) => {
                let mode = session.mode;
                let target = session.candidate.clone();
                self.active_session = Some(session);
                if let Some(mut retained) = self.retained_killswitch.take() {
                    retained.disarm();
                }
                let _ = self
                    .state_tx
                    .send(ConnectionState::Connected { mode, target });
                if let Some(r) = reply {
                    let _ = r.send(Ok(()));
                }
            }
            Ok(Err(e)) => {
                let err_msg = format!("{}", e);
                let _ = self.state_tx.send(ConnectionState::Failed(err_msg));
                if let Some(r) = reply {
                    let _ = r.send(Err(e));
                }
            }
            Err(_) => {
                // Task was aborted via cancel/disconnect
                let _ = self.state_tx.send(ConnectionState::Disconnected);
                if let Some(r) = reply {
                    let _ = r.send(Err(ServiceError::Vpn("Connection cancelled".into())));
                }
            }
        }
    }

    async fn abort_in_flight_operations(&mut self) {
        if let Some(cancel) = self.connecting_cancel.take() {
            cancel.cancel();
        }
        if let Some(handle) = self.connecting_handle.take() {
            handle.abort();
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        }
        if let Some(reply) = self.connecting_reply.take() {
            let _ = reply.send(Err(ServiceError::Vpn("Cancelled by user".into())));
        }

        if let Some(cancel) = self.reconnecting_cancel.take() {
            cancel.cancel();
        }
        if let Some(handle) = self.reconnecting_handle.take() {
            handle.abort();
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn perform_connect_task(
        guardian: Arc<GuardianClient>,
        candidate: ProxyCandidate,
        access_token: String,
        token_provider: Option<Arc<dyn TokenProvider>>,
        mode: ConnectionMode,
        cancel_token: CancellationToken,
        supervision_tx: mpsc::Sender<SupervisionEvent>,
        forwarder_handle: JoinHandle<()>,
        custom_roots: Option<rustls::RootCertStore>,
        inherited_proxy_guard: Option<SystemProxyGuard>,
    ) -> Result<SessionContext, ServiceError> {
        let mut tracker = TaskTracker::new();
        // Track the caller's supervision-event forwarder so it is aborted
        // together with everything else: on success when the session is
        // torn down, and on an early failure via the new TaskTracker::drop
        // above. Previously this small forwarder task was never tracked at
        // all and could outlive its session indefinitely (S-8).
        tracker.track(forwarder_handle);

        if cancel_token.is_cancelled() {
            return Err(ServiceError::Vpn("Cancelled".into()));
        }

        // 1. Guardian token fetch (10s timeout)
        let pass_fut = guardian.fetch_proxy_pass(guardian.endpoint(), &access_token);
        let proxy_pass = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(ServiceError::Vpn("Connection cancelled by user".into()));
            }
            res = tokio::time::timeout(Duration::from_secs(10), pass_fut) => {
                match res {
                    Ok(Ok(p)) => p,
                    Ok(Err(crate::guardian::client::GuardianError::TokenInvalid)) => {
                        return Err(ServiceError::Vpn(
                            "Mozilla rejected access token. Please sign in again.".into(),
                        ));
                    }
                    Ok(Err(crate::guardian::client::GuardianError::QuotaExceeded)) => {
                        return Err(ServiceError::Vpn(
                            "Your 50GB monthly bandwidth quota is exhausted.".into(),
                        ));
                    }
                    Ok(Err(e)) => {
                        return Err(ServiceError::Vpn(format!(
                            "Failed to obtain proxy pass: {}",
                            e
                        )));
                    }
                    Err(_) => {
                        return Err(ServiceError::Vpn("Guardian token request timed out".into()));
                    }
                }
            }
        };

        if cancel_token.is_cancelled() {
            return Err(ServiceError::Vpn("Cancelled".into()));
        }

        // 2. DNS resolution and pinning (5s timeout)
        let edge_resolver = crate::vpn::edge_resolver::EdgeResolver::new();
        let host = candidate.host.clone();
        let port = candidate.port;

        let socket_addr = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(ServiceError::Vpn("Connection cancelled by user".into()));
            }
            res = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::task::spawn_blocking(move || edge_resolver.resolve_and_pin(&host, port))
            ) => {
                match res {
                    Ok(Ok(Ok(addr))) => addr,
                    Ok(Ok(Err(e))) => {
                        return Err(ServiceError::DnsResolution(format!("{}: {}", candidate.host, e)));
                    }
                    Ok(Err(e)) => {
                        return Err(ServiceError::DnsResolution(format!("DNS task join error: {}", e)));
                    }
                    Err(_) => {
                        return Err(ServiceError::DnsResolution(format!("{}: resolution timed out", candidate.host)));
                    }
                }
            }
        };

        if cancel_token.is_cancelled() {
            return Err(ServiceError::Vpn("Cancelled".into()));
        }

        // Full mode only tunnels IPv4: reject an IPv6-only edge BEFORE doing
        // any network work instead of connecting first and failing later (S-8).
        if mode == ConnectionMode::Full && socket_addr.is_ipv6() {
            return Err(ServiceError::Vpn(
                "Edge resolved to IPv6 unsupported for IPv4 full tunneling".into(),
            ));
        }

        // Detect physical interface for socket binding and routing if in Full mode
        let physical_info = if mode == ConnectionMode::Full {
            crate::vpn::routing::detect_default_gateway_and_interface().ok()
        } else {
            None
        };
        let bind_if = physical_info.map(|(_, idx)| idx);

        // 3. Connect H2 session with supervision and timeouts
        let h2_fut = H2UpstreamSession::connect_addr_with_supervision_and_roots(
            socket_addr,
            &candidate.host,
            &proxy_pass.token,
            Some(supervision_tx.clone()),
            bind_if,
            custom_roots,
        );

        let h2_session = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(ServiceError::Vpn("Connection cancelled by user".into()));
            }
            res = h2_fut => {
                match res {
                    Ok(s) => Arc::new(s),
                    Err(e) => return Err(ServiceError::Vpn(format!("HTTP/2 connect error: {:?}", e))),
                }
            }
        };

        let mut packet_pump = None;
        let mut route_guard = None;
        let mut local_proxy = None;
        let mut system_proxy_guard = None;
        let mut killswitch_guard = None;
        // Consumed by the ProxyOnly branch on reconnects (see below).
        let mut inherited_proxy_guard = inherited_proxy_guard;

        match mode {
            ConnectionMode::Full => {
                let edge_ipv4 = match socket_addr.ip() {
                    IpAddr::V4(ipv4) => ipv4,
                    IpAddr::V6(_) => {
                        return Err(ServiceError::Vpn(
                            "Edge resolved to IPv6 unsupported for IPv4 full tunneling".into(),
                        ));
                    }
                };

                let (physical_gw, physical_if_idx) = match physical_info {
                    Some(info) => info,
                    None => crate::vpn::routing::detect_default_gateway_and_interface().map_err(
                        |e| ServiceError::Vpn(format!("Gateway detection error: {:?}", e)),
                    )?,
                };

                let device = create_tun_device()?;

                let rg = RouteManager::install_vpn_routes(
                    edge_ipv4,
                    physical_gw,
                    physical_if_idx,
                    device.ip(),
                    device.adapter_index(),
                )
                .map_err(|e| ServiceError::Vpn(format!("Route error: {:?}", e)))?;
                route_guard = Some(rg);

                // Native kill switch (WFP on Windows, iptables on Linux) (R-8).
                // Journaled via the shared recovery journal: the iptables
                // chains persist across a crash/SIGKILL (unlike the WFP
                // dynamic session), so the next startup's recover_if_dirty
                // needs this record to remove them (external review, H2b).
                let mut ksg = crate::vpn::killswitch::KillSwitchGuard::new_with_journal(
                    crate::vpn::killswitch::platform_firewall_backend(),
                    Some(crate::vpn::recovery_journal::RecoveryJournal::shared_default()),
                );
                let policy = crate::vpn::killswitch::KillSwitchPolicy {
                    kill_switch_enabled: true,
                    block_ipv6_leaks: true,
                    edge_ip: Some(edge_ipv4),
                    wintun_if_index: Some(device.adapter_index()),
                    wintun_local_ip: Some(device.ip()),
                };
                // A kill switch that silently fails to install defeats the
                // whole point of Full mode (fail-closed): the review found
                // this previously only logged a warning and continued,
                // reporting `Connected { Full }` with no traffic blocking
                // in place at all. Treat it as fatal and let the `?` below
                // roll back everything already set up in this function.
                ksg.apply(&policy)
                    .map_err(|e| ServiceError::Vpn(format!("Kill switch install failed: {}", e)))?;
                killswitch_guard = Some(ksg);

                let pump = PacketPump::new();
                let pump_handle = pump.start(
                    device.clone(),
                    h2_session.clone(),
                    Some(supervision_tx.clone()),
                );
                tracker.track(pump_handle);
                packet_pump = Some(pump);
            }
            ConnectionMode::ProxyOnly => {
                let proxy = LocalProxyServer::new();
                let proxy_upstream = h2_session.clone();
                // Bind errors are fatal now (H1): enabling the system
                // proxy against a port nobody listens on would report
                // Connected while traffic dies (or reaches a stranger's
                // listener). start() binds before spawning, so this `?`
                // fires before any system state changes.
                proxy
                    .start(DEFAULT_LOCAL_PROXY_PORT, proxy_upstream)
                    .await
                    .map_err(|e| {
                        ServiceError::Vpn(format!(
                            "Local proxy failed to bind 127.0.0.1:{}: {}",
                            DEFAULT_LOCAL_PROXY_PORT, e
                        ))
                    })?;
                local_proxy = Some(proxy);

                // On a reconnect, the previous session's system-proxy
                // guard is inherited: it still holds the ORIGINAL
                // pre-VPN settings as its backup and the OS proxy never
                // stopped pointing at the local listener, so there is
                // no direct-traffic window and no backup-of-our-own-
                // settings corruption (external review, M4). A fresh
                // connect enables a new guard instead.
                let spg = match inherited_proxy_guard.take() {
                    Some(g) => g,
                    None => match SystemProxyGuard::enable(DEFAULT_LOCAL_PROXY_PORT) {
                        Ok(g) => g,
                        Err(e) => {
                            if let Some(p) = local_proxy.take() {
                                p.stop().await;
                            }
                            return Err(ServiceError::Vpn(format!(
                                "System proxy error: {:?}",
                                e
                            )));
                        }
                    },
                };
                system_proxy_guard = Some(spg);
            }
        }

        // Network-change watcher (S-5, B5). Integrates Windows NotifyRouteChange2
        // for immediate event-driven detection, with a debounced 5-second
        // polling interval as fallback.
        if let IpAddr::V4(watch_edge) = socket_addr.ip() {
            let net_cancel = cancel_token.clone();
            let net_sup = supervision_tx.clone();
            tracker.spawn(async move {
                let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<()>(16);
                let _sub = crate::vpn::routing::platform_subscribe_route_changes(notify_tx);

                let last = crate::vpn::routing::platform_best_route(watch_edge);
                let mut pending: Option<Option<(std::net::Ipv4Addr, u32)>> = None;
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = net_cancel.cancelled() => break,
                        Some(()) = notify_rx.recv() => {
                            // Immediate notification from Windows NotifyRouteChange2.
                            // 500ms debounce to allow route table stabilization.
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            let now = crate::vpn::routing::platform_best_route(watch_edge);
                            if now != last {
                                tracing::warn!("Physical route to edge changed (via NotifyRouteChange2): {:?} -> {:?}", last, now);
                                let _ = net_sup.send(SupervisionEvent::NetworkChanged).await;
                                break;
                            }
                        }
                        _ = interval.tick() => {
                            let now = crate::vpn::routing::platform_best_route(watch_edge);
                            if now == last {
                                pending = None;
                            } else if pending == Some(now) {
                                tracing::warn!("Physical route to edge changed: {:?} -> {:?}", last, now);
                                let _ = net_sup.send(SupervisionEvent::NetworkChanged).await;
                                break;
                            } else {
                                pending = Some(now);
                            }
                        }
                    }
                }
            });
        }

        // PING keepalive loop with deadline (R-7)
        let ping_h2 = h2_session.clone();
        let ping_sup = supervision_tx.clone();
        let ping_cancel = cancel_token.clone();
        tracker.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = ping_cancel.cancelled() => break,
                    _ = interval.tick() => {
                        if let Err(e) = ping_h2.ping_with_timeout(Duration::from_secs(5)).await {
                            tracing::warn!("H2 keepalive ping failed: {:?}", e);
                            let _ = ping_sup.send(SupervisionEvent::PingFailed).await;
                            break;
                        }
                    }
                }
            }
        });

        // Token renewal worker: prefer the live provider so renewal
        // fetches a fresh token each cycle (see Connect's
        // token_provider); fall back to the connect-time token when no
        // provider was supplied.
        let renewal_worker = TokenRenewalWorker::new();
        let renewal_handle = match token_provider {
            Some(provider) => renewal_worker.start_with_provider(
                guardian.clone(),
                guardian.endpoint().to_string(),
                provider,
                h2_session.clone(),
                proxy_pass.expires_at_epoch_seconds,
            ),
            None => renewal_worker.start(
                guardian.clone(),
                guardian.endpoint().to_string(),
                access_token.clone(),
                h2_session.clone(),
                proxy_pass.expires_at_epoch_seconds,
            ),
        };
        tracker.track(renewal_handle);

        Ok(SessionContext {
            candidate,
            access_token,
            mode,
            cancel_token,
            tracker,
            h2_session,
            renewal_worker,
            packet_pump,
            local_proxy,
            system_proxy_guard,
            route_guard,
            killswitch_guard,
        })
    }

    async fn perform_disconnect(&mut self) {
        // A retained kill switch (Failed state after reconnect
        // exhaustion) comes down only here: an explicit disconnect or
        // cancel is the user accepting direct traffic again.
        if let Some(mut retained) = self.retained_killswitch.take() {
            retained.clean();
        }
        if let Some(mut session) = self.active_session.take() {
            session.cancel_token.cancel();

            if let Some(proxy) = session.local_proxy.take() {
                proxy.stop().await;
            }

            if let Some(pump) = session.packet_pump.take() {
                pump.stop();
            }

            if let Some(mut ks) = session.killswitch_guard.take() {
                ks.clean();
            }

            session.renewal_worker.stop();
            // Forcibly close the old upstream TCP/TLS connection and stop
            // its background driver task so it cannot linger after the
            // session is considered gone (S-8).
            session.h2_session.shutdown().await;
            session.tracker.abort_and_join_all().await;
        }
        self.edge_resolver.clear_cache();
    }

    async fn handle_supervision(&mut self, event: SupervisionEvent) {
        tracing::warn!("Supervision event triggered: {:?}", event);
        if let Some(session) = self.active_session.take() {
            let target = session.candidate.clone();
            let mode = session.mode;
            let token = session.access_token.clone();
            // Reconnect attempts renew through the same live provider
            // the original Connect supplied, not the stale session token.
            let provider_clone = self.token_provider.clone();

            // Clean up the old session's data path, but deliberately do NOT
            // clean the kill switch here: it is carried forward into the
            // reconnect attempts below so that Full-mode traffic stays
            // fail-closed for the whole reconnect window instead of having
            // a gap between the old filters coming down and new ones going
            // up (S-2 in the round-3 review). Route guard is still torn
            // down and freshly reinstalled by each attempt; duplicating
            // split-routes across an old and new RouteGuard risks the
            // backend rejecting a duplicate add, which is a worse failure
            // mode than briefly reinstalling routes.
            let mut old_session = session;
            old_session.cancel_token.cancel();
            if let Some(proxy) = old_session.local_proxy.take() {
                proxy.stop().await;
            }
            if let Some(pump) = old_session.packet_pump.take() {
                pump.stop();
            }
            old_session.renewal_worker.stop();
            old_session.h2_session.shutdown().await;
            old_session.tracker.abort_and_join_all().await;
            let carried_killswitch = old_session.killswitch_guard.take();
            // ProxyOnly: the system proxy guard is carried too, so the
            // OS proxy keeps pointing at the (restarting) local proxy
            // for the whole reconnect window instead of being restored
            // to direct traffic the moment the old session drops (M4).
            let carried_proxy_guard = old_session.system_proxy_guard.take();
            drop(old_session.route_guard.take());

            let cancel_token = CancellationToken::new();
            let cancel_clone = cancel_token.clone();
            let state_tx = self.state_tx.clone();
            let guardian = self.guardian.clone();
            let cmd_tx = self.cmd_tx.clone();
            let roots_clone = self.custom_roots.clone();

            let reconnect_handle = tokio::spawn(async move {
                let mut carried_killswitch = carried_killswitch;
                let mut carried_proxy_guard = carried_proxy_guard;

                for attempt in 1..=5 {
                    if cancel_clone.is_cancelled() {
                        return;
                    }

                    let _ = state_tx.send(ConnectionState::Reconnecting {
                        attempt,
                        target: target.clone(),
                    });

                    let backoff_secs = 1u64 << (attempt - 1).min(4);
                    let jitter_ms = rand::random::<u64>() % 500;
                    let delay =
                        Duration::from_secs(backoff_secs) + Duration::from_millis(jitter_ms);

                    tokio::select! {
                        _ = cancel_clone.cancelled() => return,
                        _ = tokio::time::sleep(delay) => {}
                    }

                    let (sup_tx, mut sup_rx) = mpsc::channel::<SupervisionEvent>(16);
                    let cmd_tx_clone = cmd_tx.clone();
                    let forwarder_handle = tokio::spawn(async move {
                        while let Some(evt) = sup_rx.recv().await {
                            let _ = cmd_tx_clone.send(ServiceCommand::Supervision(evt)).await;
                        }
                    });

                    match Self::perform_connect_task(
                        guardian.clone(),
                        target.clone(),
                        token.clone(),
                        provider_clone.clone(),
                        mode,
                        cancel_clone.clone(),
                        sup_tx,
                        forwarder_handle,
                        roots_clone.clone(),
                        carried_proxy_guard.take(),
                    )
                    .await
                    {
                        Ok(new_session) => {
                            // The new attempt installed its own kill switch
                            // (inside perform_connect_task). The carried
                            // guard is DISARMED, not cleaned: both guards
                            // manage the same backend state, and a clean()
                            // here would tear down the protection the new
                            // session just installed (chain-global on
                            // Linux, id-scoped on Windows).
                            if let Some(mut carried) = carried_killswitch.take() {
                                carried.disarm();
                            }

                            // Hand the fully-built session back to the actor
                            // directly. Sending `Connect` here (the previous
                            // implementation) was rejected by the actor's
                            // own guard against reconnecting while already
                            // `Reconnecting`, which left the app stuck
                            // forever with a live, working session nobody
                            // ever installed (S-2).
                            let _ = cmd_tx
                                .send(ServiceCommand::ReconnectCompleted {
                                    session: Box::new(new_session),
                                })
                                .await;
                            return;
                        }
                        Err(e) => {
                            tracing::warn!("Reconnection attempt {} failed: {:?}", attempt, e);
                        }
                    }
                }

                if cancel_clone.is_cancelled() {
                    // User cancelled mid-reconnect: dropping the guards
                    // here restores direct traffic, which is what a
                    // cancel means. (Drop also covers task aborts.)
                    return;
                }

                // All attempts exhausted. Full mode: do NOT drop the
                // carried kill switch — that removed the filters and
                // left the machine fail-open in the Failed state (H3).
                // Hand it to the actor for retention; it comes down on
                // an explicit Disconnect/Cancel, or is disarmed when a
                // new session's kill switch supersedes it. ProxyOnly:
                // the carried proxy guard drops here, restoring the
                // original system proxy — the session is over, so
                // pointing the OS at a dead local listener would be
                // the worse failure.
                if let Some(carried) = carried_killswitch.take() {
                    let _ = cmd_tx
                        .send(ServiceCommand::RetainKillSwitch {
                            guard: Box::new(carried),
                        })
                        .await;
                    let _ = state_tx.send(ConnectionState::Failed(
                        "Upstream connection dropped; maximum reconnection attempts reached. The kill switch stays active: traffic remains blocked until you disconnect or reconnect.".into(),
                    ));
                } else {
                    let _ = state_tx.send(ConnectionState::Failed(
                        "Upstream connection dropped; maximum reconnection attempts reached.".into(),
                    ));
                }
            });

            self.reconnecting_cancel = Some(cancel_token);
            self.reconnecting_handle = Some(reconnect_handle);
        }
    }
}
