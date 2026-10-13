use ifoxy_windows::auth::fxa_client::FxaClient;
use ifoxy_windows::guardian::challenge_solver::FastlyChallengeSolver;
use ifoxy_windows::guardian::client::GuardianClient;
use ifoxy_windows::http_client::create_client_with_root_cert;
use ifoxy_windows::servers::client::ServerListClient;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

struct TestTlsHarness {
    pub ca_cert_der: Vec<u8>,
    pub server_addr: SocketAddr,
    _server_task: tokio::task::JoinHandle<()>,
}

async fn start_test_https_server(ca_name: &str) -> TestTlsHarness {
    // 1. Generate Test CA
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_dn = rcgen::DistinguishedName::new();
    ca_dn.push(rcgen::DnType::CommonName, ca_name);
    ca_params.distinguished_name = ca_dn;
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_cert_der = ca_cert.der().to_vec();

    // 2. Generate Server Cert signed by Test CA
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

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = tls_stream.read(&mut buf).await {
                        if n > 0 {
                            let body = b"{\"status\":\"ok\",\"token\":\"dummy\",\"data\":[],\"servers\":[],\"sessionToken\":\"dummy\",\"verified\":true,\"access_token\":\"tok\"}";
                            let header = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = tls_stream.write_all(header.as_bytes()).await;
                            let _ = tls_stream.write_all(body).await;
                        }
                    }
                }
            });
        }
    });

    TestTlsHarness {
        ca_cert_der,
        server_addr,
        _server_task: server_task,
    }
}

#[tokio::test]
async fn test_all_four_clients_complete_tls_with_trusted_ca() {
    let harness = start_test_https_server("iFoxy Trusted CA").await;
    let base_url = format!("https://localhost:{}", harness.server_addr.port());

    // Build client using centralized http_client with the test root CA added
    let trusted_client = create_client_with_root_cert(&harness.ca_cert_der)
        .expect("Must build client with root certificate");

    // 1. FastlyChallengeSolver completes TLS handshake
    let solver = FastlyChallengeSolver::with_client(trusted_client.clone());
    let solver_res = solver.solve_and_install(&base_url).await;
    assert!(
        solver_res.is_ok(),
        "FastlyChallengeSolver must complete TLS handshake: {:?}",
        solver_res
    );

    // 2. ServerListClient completes TLS handshake
    let server_client = ServerListClient::with_client(trusted_client.clone());
    let server_res = server_client
        .fetch_countries_from(&format!("{}/api/servers", base_url))
        .await;
    assert!(
        server_res.is_ok(),
        "ServerListClient must complete TLS handshake: {:?}",
        server_res
    );

    // 3. GuardianClient completes TLS handshake
    let guardian_client = GuardianClient::with_client(trusted_client.clone());
    let guardian_res = guardian_client
        .fetch_proxy_pass(&base_url, "test_bearer_token")
        .await;
    // We expect the TLS handshake to succeed (even if JSON schema mismatch gives parse error, not a TLS connect error)
    if let Err(e) = &guardian_res {
        let err_str = e.to_string();
        assert!(
            !err_str.contains("certificate") && !err_str.contains("handshake"),
            "GuardianClient failed at TLS layer: {:?}",
            e
        );
    }

    // 4. FxaClient completes TLS handshake
    let fxa_client = FxaClient::with_client_and_server(trusted_client.clone(), &base_url);
    let fxa_res = fxa_client.login("user@example.com", "password123").await;
    if let Err(e) = &fxa_res {
        let err_str = e.to_string();
        assert!(
            !err_str.contains("certificate") && !err_str.contains("handshake"),
            "FxaClient failed at TLS layer: {:?}",
            e
        );
    }
}

#[tokio::test]
async fn test_all_clients_strictly_reject_untrusted_certificate() {
    // Harness with a completely untrusted, rogue CA
    let untrusted_harness = start_test_https_server("Untrusted Rogue CA").await;
    let untrusted_url = format!("https://localhost:{}", untrusted_harness.server_addr.port());

    // Standard client with ONLY legitimate roots (no rogue CA)
    let client = reqwest::Client::builder().build().unwrap();

    // 1. FastlyChallengeSolver rejected
    let solver = FastlyChallengeSolver::with_client(client.clone());
    let solver_res = solver.solve_and_install(&untrusted_url).await;
    assert!(
        solver_res.is_err(),
        "FastlyChallengeSolver must reject untrusted certificate"
    );

    // 2. ServerListClient rejected
    let server_client = ServerListClient::with_client(client.clone());
    let server_res = server_client
        .fetch_countries_from(&format!("{}/api/servers", untrusted_url))
        .await;
    assert!(
        server_res.is_err(),
        "ServerListClient must reject untrusted certificate"
    );

    // 3. GuardianClient rejected
    let guardian_client = GuardianClient::with_client(client.clone());
    let guardian_res = guardian_client
        .fetch_proxy_pass(&untrusted_url, "token")
        .await;
    assert!(
        guardian_res.is_err(),
        "GuardianClient must reject untrusted certificate"
    );

    // 4. FxaClient rejected
    let fxa_client = FxaClient::with_client_and_server(client.clone(), &untrusted_url);
    let fxa_res = fxa_client.login("user@example.com", "pass").await;
    assert!(
        fxa_res.is_err(),
        "FxaClient must reject untrusted certificate"
    );
}

#[tokio::test]
async fn test_clean_machine_default_client_has_webpki_roots_loaded() {
    let client = ifoxy_windows::http_client::create_default_client()
        .expect("Default client creation must succeed with webpki-roots");

    // All four clients constructed with default constructors must initialize without error
    let _fxa = FxaClient::new();
    let _guardian = GuardianClient::new();
    let _server_list = ServerListClient::new();
    let _solver = FastlyChallengeSolver::new();

    // Verify client can connect to an endpoint without crashing or missing roots
    let res = client.get("https://example.com").send().await;
    // On machines with or without internet, reqwest should either succeed or fail at DNS/network,
    // NEVER fail with "rustls: No root certificates configured" or "manual-roots" builder error.
    if let Err(e) = res {
        let err_str = e.to_string();
        assert!(
            !err_str.contains("no certificates") && !err_str.contains("manual-roots"),
            "Client must not fail due to missing root certificates: {:?}",
            err_str
        );
    }
}
