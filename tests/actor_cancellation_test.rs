use ifoxy_windows::guardian::client::GuardianClient;
use ifoxy_windows::servers::model::ProxyCandidate;
use ifoxy_windows::service::state_machine::{
    ServiceCommand, StateMachineActor, SupervisionEvent,
};
use ifoxy_windows::service::vpn_service::{ConnectionMode, ConnectionState, VpnService};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_cancel_preempts_stalled_connecting_within_1_second() {
    // 1. Setup a blackhole TCP listener that accepts connections but never replies (simulating stalled edge)
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blackhole_port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((_sock, _)) = listener.accept().await {
            // Intentionally hold the socket and never send any data or complete handshake
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    let service = Arc::new(VpnService::new());
    let mut state_rx = service.subscribe_state();

    let candidate = ProxyCandidate {
        host: "127.0.0.1".to_string(),
        port: blackhole_port,
        country_code: "US".to_string(),
        country_name: "United States".to_string(),
        city_code: "TST".to_string(),
        city_name: Some("Test".to_string()),
        latency_ms: None,
    };

    let service_clone = service.clone();
    let connect_handle = tokio::spawn(async move {
        // Will attempt connect and block
        let _ = service_clone
            .start_connect(candidate, "dummy_token", ConnectionMode::ProxyOnly)
            .await;
    });

    // Wait until state is Connecting
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(*state_rx.borrow(), ConnectionState::Connecting);

    // 2. User clicks Cancel!
    let cancel_start = std::time::Instant::now();
    service.cancel();

    // 3. State MUST become Disconnected within 1 second!
    let mut transitioned = false;
    let timeout = tokio::time::sleep(Duration::from_secs(1));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Ok(()) = state_rx.changed() => {
                if *state_rx.borrow() == ConnectionState::Disconnected {
                    transitioned = true;
                    break;
                }
            }
            _ = &mut timeout => {
                break;
            }
        }
    }

    let elapsed = cancel_start.elapsed();
    assert!(
        transitioned,
        "Cancel must preempt stalled connect within 1s, but state is {:?} after {:?}",
        *state_rx.borrow(),
        elapsed
    );

    connect_handle.abort();
}

#[tokio::test]
async fn test_cancel_during_reconnecting_preempts_immediately() {
    let guardian = Arc::new(GuardianClient::new());
    let (cmd_tx, mut state_rx) = StateMachineActor::spawn(guardian);

    // Simulate supervision trigger of ConnectionDropped
    cmd_tx
        .send(ServiceCommand::Supervision(
            SupervisionEvent::ConnectionDropped,
        ))
        .await
        .unwrap();

    // Now send Cancel
    let cancel_start = std::time::Instant::now();
    cmd_tx.send(ServiceCommand::Cancel).await.unwrap();

    // State must be Disconnected within 500ms
    let mut clean_disconnect = false;
    let timeout = tokio::time::sleep(Duration::from_millis(500));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Ok(()) = state_rx.changed() => {
                if *state_rx.borrow() == ConnectionState::Disconnected {
                    clean_disconnect = true;
                    break;
                }
            }
            _ = &mut timeout => {
                if *state_rx.borrow() == ConnectionState::Disconnected {
                    clean_disconnect = true;
                }
                break;
            }
        }
    }

    assert!(
        clean_disconnect,
        "Actor must immediately process Cancel during reconnection within 500ms (elapsed: {:?})",
        cancel_start.elapsed()
    );
}

#[tokio::test]
async fn test_network_changed_and_token_refreshed_handling() {
    let service = VpnService::new();
    assert_eq!(service.get_state(), ConnectionState::Disconnected);

    // Notify network changed
    service.notify_network_changed().await;
    assert_eq!(service.get_state(), ConnectionState::Disconnected);

    // Notify token refreshed
    service.notify_token_refreshed("fresh_token_12345").await;
    assert_eq!(service.get_state(), ConnectionState::Disconnected);
}
