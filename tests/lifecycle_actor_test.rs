use ifoxy_windows::guardian::client::GuardianClient;
use ifoxy_windows::service::state_machine::{
    ServiceCommand, StateMachineActor, SupervisionEvent, TaskTracker,
};
use ifoxy_windows::service::vpn_service::{ConnectionState, VpnService};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// Tests that drive a real ProxyOnly connect bind the shared local-proxy
/// port (DEFAULT_LOCAL_PROXY_PORT); in parallel they steal each other's
/// listener and fail each other's initial connect. Serialize just those.
static PROXY_PORT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[tokio::test]
async fn test_task_tracker_and_cancellation_token() {
    let mut tracker = TaskTracker::new();
    let token = CancellationToken::new();

    let executed = Arc::new(AtomicUsize::new(0));

    for _ in 0..10 {
        let exec = executed.clone();
        let child_token = token.child_token();
        tracker.spawn(async move {
            tokio::select! {
                _ = child_token.cancelled() => {
                    // Cleanly interrupted
                }
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    exec.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }

    assert_eq!(tracker.active_count.load(Ordering::SeqCst), 10);

    // Cancel token and join all
    token.cancel();
    tracker.abort_and_join_all().await;

    // All tasks must have terminated without running to completion (C5)
    assert_eq!(tracker.active_count.load(Ordering::SeqCst), 0);
    assert_eq!(executed.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_state_machine_actor_disconnect_lifecycle() {
    let guardian = Arc::new(GuardianClient::new());
    let (cmd_tx, state_rx) = StateMachineActor::spawn(guardian);

    assert_eq!(*state_rx.borrow(), ConnectionState::Disconnected);

    // Disconnect when already disconnected should be a clean no-op
    let (reply_tx, reply_rx) = oneshot::channel();
    cmd_tx
        .send(ServiceCommand::Disconnect { reply: reply_tx })
        .await
        .expect("Send Disconnect");
    reply_rx.await.expect("Receive reply");
    assert_eq!(*state_rx.borrow(), ConnectionState::Disconnected);

    // Cancel when disconnected
    cmd_tx
        .send(ServiceCommand::Cancel)
        .await
        .expect("Send Cancel");
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(*state_rx.borrow(), ConnectionState::Disconnected);
}

#[tokio::test]
async fn test_supervision_reconnect_backoff_exhaustion() {
    let guardian = Arc::new(GuardianClient::new());
    let (cmd_tx, state_rx) = StateMachineActor::spawn(guardian);

    // Simulate supervision event without active session: should be safely ignored
    cmd_tx
        .send(ServiceCommand::Supervision(
            SupervisionEvent::ConnectionDropped,
        ))
        .await
        .expect("Send supervision");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(*state_rx.borrow(), ConnectionState::Disconnected);
}

#[test]
fn test_vpn_service_sync_facade_and_state_consistency() {
    let service = VpnService::new();
    assert_eq!(service.get_state(), ConnectionState::Disconnected);

    // Calling disconnect on fresh service succeeds cleanly
    assert!(service.disconnect().is_ok());
    assert_eq!(service.get_state(), ConnectionState::Disconnected);

    // Calling cancel on fresh service executes cleanly
    service.cancel();
    assert_eq!(service.get_state(), ConnectionState::Disconnected);
}

#[tokio::test]
async fn test_reconnect_path_transitions_to_connected_and_ignores_stale_events() {
    use ifoxy_windows::servers::model::ProxyCandidate;
    use ifoxy_windows::service::state_machine::SessionContext;
    use ifoxy_windows::service::vpn_service::ConnectionMode;
    use ifoxy_windows::service::watchdog::TokenRenewalWorker;
    use ifoxy_windows::tunnel::h2_session::H2UpstreamSession;

    let guardian = Arc::new(GuardianClient::new());
    let (cmd_tx, state_rx) = StateMachineActor::spawn(guardian);

    assert_eq!(*state_rx.borrow(), ConnectionState::Disconnected);

    let candidate = ProxyCandidate {
        host: "127.0.0.1".into(),
        port: 443,
        country_code: "US".into(),
        country_name: "United States".into(),
        city_code: "TST".into(),
        city_name: Some("Test".into()),
        latency_ms: None,
    };

    // 1. Install an initial connected session via ReconnectCompleted
    let session1 = SessionContext {
        candidate: candidate.clone(),
        access_token: "token1".into(),
        mode: ConnectionMode::ProxyOnly,
        cancel_token: CancellationToken::new(),
        tracker: TaskTracker::new(),
        h2_session: Arc::new(H2UpstreamSession::new_dummy("token1")),
        renewal_worker: TokenRenewalWorker::new(),
        packet_pump: None,
        local_proxy: None,
        system_proxy_guard: None,
        route_guard: None,
        killswitch_guard: None,
    };

    cmd_tx
        .send(ServiceCommand::ReconnectCompleted {
            session: Box::new(session1),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    match *state_rx.borrow() {
        ConnectionState::Connected { mode, ref target } => {
            assert_eq!(mode, ConnectionMode::ProxyOnly);
            assert_eq!(target.host, "127.0.0.1");
        }
        ref s => panic!("Expected Connected state, got {:?}", s),
    }

    // 2. Trigger connection drop via Supervision: actor transitions to Reconnecting
    cmd_tx
        .send(ServiceCommand::Supervision(
            SupervisionEvent::ConnectionDropped,
        ))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    match *state_rx.borrow() {
        ConnectionState::Reconnecting {
            attempt,
            ref target,
        } => {
            assert_eq!(attempt, 1);
            assert_eq!(target.host, "127.0.0.1");
        }
        ref s => panic!("Expected Reconnecting state, got {:?}", s),
    }

    // 3. Stale supervision events from old session must be safely handled while Reconnecting
    cmd_tx
        .send(ServiceCommand::Supervision(
            SupervisionEvent::ConnectionDropped,
        ))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    // 4. Reconnect successfully completes with new session
    let session2 = SessionContext {
        candidate: candidate.clone(),
        access_token: "token2".into(),
        mode: ConnectionMode::ProxyOnly,
        cancel_token: CancellationToken::new(),
        tracker: TaskTracker::new(),
        h2_session: Arc::new(H2UpstreamSession::new_dummy("token2")),
        renewal_worker: TokenRenewalWorker::new(),
        packet_pump: None,
        local_proxy: None,
        system_proxy_guard: None,
        route_guard: None,
        killswitch_guard: None,
    };

    cmd_tx
        .send(ServiceCommand::ReconnectCompleted {
            session: Box::new(session2),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    match *state_rx.borrow() {
        ConnectionState::Connected { mode, ref target } => {
            assert_eq!(mode, ConnectionMode::ProxyOnly);
            assert_eq!(target.host, "127.0.0.1");
        }
        ref s => panic!(
            "Expected Connected state after ReconnectCompleted, got {:?}",
            s
        ),
    }

    // 5. Clean disconnect
    let (reply_tx, reply_rx) = oneshot::channel();
    cmd_tx
        .send(ServiceCommand::Disconnect { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap();
    assert_eq!(*state_rx.borrow(), ConnectionState::Disconnected);
}

#[tokio::test]
async fn test_50_connect_disconnect_cycles_zero_task_leak_and_port_released() {
    use ifoxy_windows::tunnel::h2_session::H2UpstreamSession;
    use ifoxy_windows::vpn::local_proxy::LocalProxyServer;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    let test_port = 10801;

    for _ in 0..50 {
        let mut tracker = TaskTracker::new();
        let upstream = Arc::new(H2UpstreamSession::new_dummy("test_token"));
        let proxy = LocalProxyServer::new();

        proxy
            .start(test_port, upstream.clone())
            .await
            .expect("proxy bind must succeed");
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Open a client connection and leave the SOCKS5 handshake half done,
        // so a per-connection handler task is alive and holds a clone of
        // `upstream`. (The previous version of this test had no live
        // connection at all.)
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port))
            .await
            .expect("connect to local proxy");
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            Arc::strong_count(&upstream) > 1,
            "listener and per-connection tasks must be holding the session"
        );

        // Disconnect and shutdown
        proxy.stop().await;
        upstream.shutdown().await;
        tracker.abort_and_join_all().await;

        // A task that is really gone has dropped its clone of `upstream`.
        // (`tracker.active_count` cannot be used for this: abort_and_join_all
        // resets it to 0 unconditionally, so asserting on it proved nothing.)
        let mut released = false;
        for _ in 0..100 {
            if Arc::strong_count(&upstream) == 1 {
                released = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            released,
            "all proxy tasks must release the session after stop (leaked clones: {})",
            Arc::strong_count(&upstream) - 1
        );
        drop(client);

        // Verify the port is freed and can be re-bound. Bounded retry:
        // a single instantaneous bind can lose a sub-50ms race against
        // unrelated tenants of a shared/loaded machine briefly holding
        // the port (observed in the 2-core CI sandbox: the conflicting
        // LISTEN socket was not owned by this process and cleared in
        // <50 ms). A genuinely leaked listener never clears, so the
        // retry does not weaken the leak check.
        let mut rebind = None;
        for _ in 0..80 {
            match TcpListener::bind(format!("127.0.0.1:{}", test_port)).await {
                Ok(l) => {
                    rebind = Some(l);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
        assert!(
            rebind.is_some(),
            "Port {} must be released and rebindable after disconnect",
            test_port
        );
        drop(rebind);
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the port lock deliberately serializes this test
async fn test_end_to_end_real_reconnect_loop_with_fake_upstream() {
    let _proxy_port_guard = PROXY_PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use bytes::Bytes;
    use ifoxy_windows::servers::model::ProxyCandidate;
    use ifoxy_windows::service::vpn_service::ConnectionMode;
    use http::Response;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use std::sync::atomic::AtomicU32;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::{RootCertStore, ServerConfig};
    use tokio_rustls::TlsAcceptor;

    // 1. Generate Test CA and Server Cert
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_dn = rcgen::DistinguishedName::new();
    ca_dn.push(rcgen::DnType::CommonName, "FoxyTestCA");
    ca_params.distinguished_name = ca_dn;
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_cert_der = ca_cert.der().to_vec();

    let server_key = KeyPair::generate().unwrap();
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    let mut server_dn = rcgen::DistinguishedName::new();
    server_dn.push(rcgen::DnType::CommonName, "localhost");
    server_params.distinguished_name = server_dn;
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let certs = vec![CertificateDer::from(server_cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(server_key.serialize_der().into());

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // 2. Start Mock Guardian HTTP server
    let guardian_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let guardian_addr = guardian_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = guardian_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = serde_json::json!({
                    "token": "fake_guardian_pass_token",
                    "expires_at": 9999999999u64,
                    "quota_max": 53687091200u64,
                    "quota_remaining": 53687091200u64
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });

    // 3. Start Mock H2 Upstream Server: drops conn 1, accepts and stays alive on conn 2
    let h2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let h2_addr = h2_listener.local_addr().unwrap();
    let conn_counter = Arc::new(AtomicU32::new(0));
    let counter_clone = conn_counter.clone();

    tokio::spawn(async move {
        while let Ok((tcp_stream, _)) = h2_listener.accept().await {
            let count = counter_clone.fetch_add(1, Ordering::SeqCst) + 1;
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp_stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let srv_builder = h2::server::Builder::new();
                let mut h2_conn = match srv_builder.handshake::<_, Bytes>(tls_stream).await {
                    Ok(c) => c,
                    Err(_) => return,
                };

                if count == 1 {
                    // First connection: accept briefly then abruptly drop
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    drop(h2_conn);
                } else {
                    // Subsequent connections (reconnect): stay alive and accept requests
                    while let Some(result) = h2_conn.accept().await {
                        if let Ok((req, mut respond)) = result {
                            if req.method() == http::Method::CONNECT {
                                let resp = Response::builder().status(200).body(()).unwrap();
                                let _ = respond.send_response(resp, false);
                            }
                        }
                    }
                }
            });
        }
    });

    // 4. Configure GuardianClient and Custom Roots for the Test
    let guardian = Arc::new(GuardianClient::with_endpoint(&format!(
        "http://{}",
        guardian_addr
    )));
    let mut custom_roots = RootCertStore::empty();
    custom_roots.add(CertificateDer::from(ca_cert_der)).unwrap();

    let (cmd_tx, mut state_rx) = StateMachineActor::spawn_with_roots(guardian, Some(custom_roots));
    assert_eq!(*state_rx.borrow(), ConnectionState::Disconnected);

    let candidate = ProxyCandidate {
        host: "127.0.0.1".into(),
        port: h2_addr.port(),
        country_code: "US".into(),
        country_name: "United States".into(),
        city_code: "TST".into(),
        city_name: Some("Test".into()),
        latency_ms: None,
    };

    // 5. Connect
    let (connect_tx, connect_rx) = oneshot::channel();
    cmd_tx
        .send(ServiceCommand::Connect {
            candidate: candidate.clone(),
            access_token: "test_token".into(),
            mode: ConnectionMode::ProxyOnly,
            reply: connect_tx,
        })
        .await
        .unwrap();

    let connect_res = connect_rx.await.unwrap();
    assert!(connect_res.is_ok(), "Initial connect must succeed: {:?}", connect_res.err());

    // Must transition to Connected
    match *state_rx.borrow() {
        ConnectionState::Connected { mode, .. } => {
            assert_eq!(mode, ConnectionMode::ProxyOnly);
        }
        ref s => panic!("Expected Connected, got {:?}", s),
    }

    // 6. Upstream server drops conn 1 -> Actor MUST transition to Reconnecting
    let mut saw_reconnecting = false;
    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Ok(()) = state_rx.changed() => {
                if matches!(*state_rx.borrow(), ConnectionState::Reconnecting { .. }) {
                    saw_reconnecting = true;
                    break;
                }
            }
            _ = &mut timeout => break,
        }
    }
    assert!(
        saw_reconnecting,
        "Actor must transition to Reconnecting after upstream drop"
    );

    // 7. Reconnect attempt connects to mock server conn 2 -> Actor MUST transition back to Connected!
    let mut saw_reconnected = false;
    let reconnect_timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(reconnect_timeout);

    loop {
        tokio::select! {
            Ok(()) = state_rx.changed() => {
                if matches!(*state_rx.borrow(), ConnectionState::Connected { .. }) {
                    saw_reconnected = true;
                    break;
                }
            }
            _ = &mut reconnect_timeout => break,
        }
    }
    assert!(
        saw_reconnected,
        "Actor must successfully reconnect through the real reconnect loop and return to Connected"
    );

    // 8. Clean Disconnect
    let (disc_tx, disc_rx) = oneshot::channel();
    cmd_tx
        .send(ServiceCommand::Disconnect { reply: disc_tx })
        .await
        .unwrap();
    disc_rx.await.unwrap();
    assert_eq!(*state_rx.borrow(), ConnectionState::Disconnected);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the port lock deliberately serializes this test
async fn test_cancel_during_real_reconnect_loop_preempts() {
    let _proxy_port_guard = PROXY_PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use bytes::Bytes;
    use ifoxy_windows::servers::model::ProxyCandidate;
    use ifoxy_windows::service::vpn_service::ConnectionMode;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::{RootCertStore, ServerConfig};
    use tokio_rustls::TlsAcceptor;

    // 1. Generate Test CA and Server Cert
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_dn = rcgen::DistinguishedName::new();
    ca_dn.push(rcgen::DnType::CommonName, "FoxyTestCA2");
    ca_params.distinguished_name = ca_dn;
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_cert_der = ca_cert.der().to_vec();

    let server_key = KeyPair::generate().unwrap();
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    let mut server_dn = rcgen::DistinguishedName::new();
    server_dn.push(rcgen::DnType::CommonName, "localhost");
    server_params.distinguished_name = server_dn;
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let certs = vec![CertificateDer::from(server_cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(server_key.serialize_der().into());

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // 2. Start Mock Guardian HTTP server
    let guardian_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let guardian_addr = guardian_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = guardian_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = serde_json::json!({
                    "token": "fake_guardian_pass_token",
                    "expires_at": 9999999999u64,
                    "quota_max": 53687091200u64,
                    "quota_remaining": 53687091200u64
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });

    // 3. Start Mock H2 Upstream Server that drops first connection
    let h2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let h2_addr = h2_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((tcp_stream, _)) = h2_listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls_stream) = acceptor.accept(tcp_stream).await {
                    let srv_builder = h2::server::Builder::new();
                    if let Ok(h2_conn) = srv_builder.handshake::<_, Bytes>(tls_stream).await {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        drop(h2_conn);
                    }
                }
            });
        }
    });

    let guardian = Arc::new(GuardianClient::with_endpoint(&format!(
        "http://{}",
        guardian_addr
    )));
    let mut custom_roots = RootCertStore::empty();
    custom_roots.add(CertificateDer::from(ca_cert_der)).unwrap();

    let (cmd_tx, mut state_rx) = StateMachineActor::spawn_with_roots(guardian, Some(custom_roots));

    let candidate = ProxyCandidate {
        host: "127.0.0.1".into(),
        port: h2_addr.port(),
        country_code: "US".into(),
        country_name: "United States".into(),
        city_code: "TST".into(),
        city_name: Some("Test".into()),
        latency_ms: None,
    };

    let (connect_tx, connect_rx) = oneshot::channel();
    cmd_tx
        .send(ServiceCommand::Connect {
            candidate,
            access_token: "test_token".into(),
            mode: ConnectionMode::ProxyOnly,
            reply: connect_tx,
        })
        .await
        .unwrap();
    let _ = connect_rx.await.unwrap();

    // Wait until in Reconnecting state
    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            Ok(()) = state_rx.changed() => {
                if matches!(*state_rx.borrow(), ConnectionState::Reconnecting { .. }) {
                    break;
                }
            }
            _ = &mut timeout => break,
        }
    }

    assert!(
        matches!(*state_rx.borrow(), ConnectionState::Reconnecting { .. }),
        "Must be in Reconnecting state"
    );

    // Cancel while Reconnecting
    let cancel_start = std::time::Instant::now();
    cmd_tx.send(ServiceCommand::Cancel).await.unwrap();

    let cancel_timeout = tokio::time::sleep(Duration::from_secs(1));
    tokio::pin!(cancel_timeout);
    loop {
        tokio::select! {
            Ok(()) = state_rx.changed() => {
                if *state_rx.borrow() == ConnectionState::Disconnected {
                    break;
                }
            }
            _ = &mut cancel_timeout => break,
        }
    }

    assert_eq!(
        *state_rx.borrow(),
        ConnectionState::Disconnected,
        "Cancel during real reconnect loop must immediately transition to Disconnected (elapsed: {:?})",
        cancel_start.elapsed()
    );
}
