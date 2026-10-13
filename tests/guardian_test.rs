use ifoxy_windows::guardian::challenge_solver::FastlyChallengeSolver;

#[test]
fn test_pow_solver() {
    use sha2::{Digest, Sha256};
    let base = "sample_challenge_base";
    let suffix = "aB";
    let mut hasher = Sha256::new();
    hasher.update((base.to_owned() + suffix).as_bytes());
    let target_hex = hex::encode(hasher.finalize());

    let solved = FastlyChallengeSolver::solve_pow(base, &target_hex);
    assert_eq!(solved, Some(suffix.to_string()));
}

#[test]
fn test_proxy_pass_deserialization() {
    use ifoxy_windows::guardian::client::ProxyPass;
    let json_data = r#"{
        "token": "secret_proxy_pass_token_xyz",
        "expires_at": 1728345600
    }"#;
    let proxy_pass: ProxyPass =
        serde_json::from_str(json_data).expect("Should deserialize ProxyPass");
    assert_eq!(proxy_pass.token, "secret_proxy_pass_token_xyz");
    assert_eq!(proxy_pass.expires_at_epoch_seconds, Some(1728345600));
}
