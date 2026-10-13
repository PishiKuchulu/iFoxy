use ifoxy_windows::service::watchdog::calculate_renewal_delay_seconds;

#[test]
fn test_renewal_delay_calculation() {
    let now = 1_000_000;
    let expires_at = now + 1800; // 30 minutes
    let delay = calculate_renewal_delay_seconds(now, Some(expires_at));
    assert_eq!(delay, 900); // at half life (15 minutes)
}

#[test]
fn test_renewal_delay_fallback_when_none() {
    let now = 1_000_000;
    let delay = calculate_renewal_delay_seconds(now, None);
    assert_eq!(delay, 240); // 4 minutes fallback
}

#[test]
fn test_renewal_delay_bounds() {
    let now = 1_000_000;
    let delay_imminent = calculate_renewal_delay_seconds(now, Some(now + 10));
    assert_eq!(delay_imminent, 15); // Floor is 15s

    let delay_far = calculate_renewal_delay_seconds(now, Some(now + 18000));
    assert_eq!(delay_far, 1800); // Ceiling is 30 minutes
}
