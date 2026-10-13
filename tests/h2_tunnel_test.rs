use ifoxy_windows::tunnel::h2_session::{build_connect_headers, H2UpstreamSession};
use http::Method;

#[test]
fn test_connect_headers_generation() {
    let req = build_connect_headers("example.com:443", "test_jwt_pass").expect("headers failed");
    assert_eq!(req.method(), Method::CONNECT);
    assert_eq!(req.uri().authority().unwrap().as_str(), "example.com:443");
    assert_eq!(
        req.headers()
            .get("proxy-authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Bearer test_jwt_pass"
    );
}

#[test]
fn test_h2_session_token_update() {
    let session = H2UpstreamSession::new_dummy("initial_token");
    assert_eq!(session.current_token(), "initial_token");
    session.update_token("new_renewed_token");
    assert_eq!(session.current_token(), "new_renewed_token");
}
