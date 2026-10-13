use ifoxy_windows::crypto::fxa_kdf::derive_auth_pw;
use ifoxy_windows::crypto::hawk::generate_hawk_header;
use ifoxy_windows::guardian::challenge_solver::FastlyChallengeSolver;
use ifoxy_windows::servers::client::ServerListClient;
use ifoxy_windows::servers::model::{VpnCity, VpnCountry, VpnProtocol, VpnServerNode};
use ifoxy_windows::service::vpn_service::{ConnectionState, VpnService};
use ifoxy_windows::service::watchdog::calculate_renewal_delay_seconds;
use ifoxy_windows::tunnel::h2_session::{build_connect_headers, H2UpstreamSession};
use ifoxy_windows::vpn::routing::{is_private_or_loopback, split_tunnel_routes};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

#[test]
fn test_end_to_end_ifoxy_workflow() {
    // 1. Password derivation & Hawk Auth
    let auth_pw = derive_auth_pw("user@example.com", "Password123!").expect("KDF failed");
    assert_eq!(auth_pw.len(), 64);

    let hawk = generate_hawk_header(
        "GET",
        "https://api.accounts.firefox.com/v1/account",
        "tok_id",
        &[0u8; 32],
        b"",
    )
    .expect("Hawk header failed");
    assert!(hawk.starts_with("Hawk id=\"tok_id\""));

    // 2. Fastly PoW Challenge Solving
    let base = "fxa_challenge_nonce";
    let suffix = "xZ";
    let mut hasher = Sha256::new();
    hasher.update((base.to_owned() + suffix).as_bytes());
    let target_hex = hex::encode(hasher.finalize());
    let solved = FastlyChallengeSolver::solve_pow(base, &target_hex);
    assert_eq!(solved, Some(suffix.to_string()));

    // 3. Server List Discovery & Candidate Selection
    let mock_country = VpnCountry {
        name: "Germany".to_string(),
        code: "DE".to_string(),
        cities: vec![VpnCity {
            name: "Frankfurt".to_string(),
            code: "FRA".to_string(),
            servers: vec![VpnServerNode {
                hostname: "fra-1.vpn.mozilla.org".to_string(),
                port: 443,
                quarantined: false,
                protocols: vec![VpnProtocol {
                    name: "connect".to_string(),
                    host: "fra-edge.fastly.net".to_string(),
                    port: 443,
                    scheme: None,
                    template_string: None,
                }],
            }],
        }],
    };
    let candidates = ServerListClient::candidates_for_country(&[mock_country], "DE");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].host, "fra-edge.fastly.net");

    // 4. Upstream Session & Token Handling
    let session = H2UpstreamSession::new_dummy("initial_pass_token");
    assert_eq!(session.current_token(), "initial_pass_token");
    let connect_req = build_connect_headers("example.com:443", &session.current_token())
        .expect("CONNECT headers failed");
    assert_eq!(connect_req.method(), "CONNECT");

    // 5. Watchdog Half-life Renewal Calculation
    let now = 1_000_000;
    let expiry = now + 1200; // 20 minutes
    let renewal_delay = calculate_renewal_delay_seconds(now, Some(expiry));
    assert_eq!(renewal_delay, 600); // 10 minutes (half life)

    // 6. Routing & Split Tunneling
    assert!(is_private_or_loopback(Ipv4Addr::new(127, 0, 0, 1)));
    assert!(is_private_or_loopback(Ipv4Addr::new(192, 168, 1, 1)));
    assert!(!is_private_or_loopback(Ipv4Addr::new(140, 82, 121, 4))); // Public IP
    let routes = split_tunnel_routes(Ipv4Addr::new(10, 254, 1, 1));
    assert_eq!(routes.len(), 2);

    // 7. VpnService Lifecycle
    let service = VpnService::new();
    assert_eq!(service.get_state(), ConnectionState::Disconnected);
    assert!(service.disconnect().is_ok());
    assert_eq!(service.get_state(), ConnectionState::Disconnected);
}
