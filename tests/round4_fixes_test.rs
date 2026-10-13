//! Tests for the fixes made in the "round 4" pass. These cover pure logic
//! that does not need Windows. Windows-API behavior (WFP, DNS, routes) still
//! has to be verified on a real machine; see docs/TESTING.md.
#![allow(clippy::assertions_on_constants)]

use ifoxy_windows::service::state_machine::{SupervisionEvent, TaskTracker};
use ifoxy_windows::vpn::netstack::{
    ESTABLISHED_IDLE_TIMEOUT, FLOW_IDLE_TIMEOUT, MAX_RETRANSMITS, MAX_RTO, RTO_DURATION,
    UPSTREAM_CONNECT_TIMEOUT,
};
use ifoxy_windows::vpn::wintun_adapter::{format_adapter_guid, IFOXY_ADAPTER_GUID};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn adapter_guid_is_formatted_as_canonical_hex_guid() {
    // The old code used u128::to_string(), which prints a decimal number.
    assert_eq!(
        format_adapter_guid(IFOXY_ADAPTER_GUID),
        "6E8E2B80-4E28-4E09-B173-7B9D7E32C021"
    );
    assert_ne!(
        format_adapter_guid(IFOXY_ADAPTER_GUID),
        IFOXY_ADAPTER_GUID.to_string()
    );
    assert_eq!(
        format_adapter_guid(0),
        "00000000-0000-0000-0000-000000000000"
    );
}

#[tokio::test]
async fn dropping_task_tracker_aborts_its_tasks() {
    // Regression test for S-8: tasks tracked by a tracker that was dropped
    // (for example after an early `?` return in the connect path) used to
    // keep running detached forever.
    let marker = Arc::new(());
    {
        let mut tracker = TaskTracker::new();
        let held = marker.clone();
        tracker.spawn(async move {
            let _held = held;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        assert_eq!(Arc::strong_count(&marker), 2);
        // tracker dropped here
    }
    // Give the runtime a moment to drop the aborted future.
    for _ in 0..50 {
        if Arc::strong_count(&marker) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        Arc::strong_count(&marker),
        1,
        "aborted task must release what it captured"
    );
}

#[test]
fn network_changed_is_a_supervision_event() {
    let e = SupervisionEvent::NetworkChanged;
    assert!(format!("{:?}", e).contains("NetworkChanged"));
}

#[test]
fn retransmission_policy_is_not_the_old_2_4_second_give_up() {
    // Old behavior: fixed 200 ms RTO, reset after 12 tries (about 2.4 s).
    assert!(MAX_RETRANSMITS > 12);
    assert_eq!(RTO_DURATION, Duration::from_millis(200));
    assert!(MAX_RTO >= Duration::from_secs(4));

    // Sum of the backed-off timeouts must be far longer than 2.4 s.
    let mut total = Duration::ZERO;
    for count in 0..MAX_RETRANSMITS {
        let backoff = 1u32 << count.min(6);
        total += (RTO_DURATION * backoff).min(MAX_RTO);
    }
    assert!(
        total > Duration::from_secs(30),
        "total give-up time {:?}",
        total
    );
}

#[test]
fn idle_and_connect_timeouts_are_sane() {
    assert!(ESTABLISHED_IDLE_TIMEOUT > FLOW_IDLE_TIMEOUT);
    assert!(UPSTREAM_CONNECT_TIMEOUT >= Duration::from_secs(5));
    assert!(UPSTREAM_CONNECT_TIMEOUT <= Duration::from_secs(60));
}
