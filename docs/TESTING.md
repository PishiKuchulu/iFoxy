# iFoxy for Windows — Testing Guide & Verification Procedures

This document outlines the automated test suite and manual verification procedures for iFoxy for Windows.

---

## 1. Automated Test Suite

The test suite consists of **121 test functions across 31 test files**
in `tests/` (attribute count, 2026-10-25). Counts by platform differ
because some tests are platform-gated (Windows-only WFP/DNS tests,
Linux-only backend tests) and 5 tests are `#[ignore]`d (admin/root
required: 3 WFP, 1 Linux TUN, 1 destructive DNS).

### Running the Full Test Suite
```powershell
cargo test
```
**Observed Summary (Linux, 2026-10-25, rustc 1.99.1, this tree):**
`112 passed; 0 failed; 1 ignored` (the ignored test requires root for
a real TUN device). Earlier versions of this document quoted 99 tests
/ 27 targets and docs/FIX_TRACKER.md quoted 107 / 27 — both stale;
do not quote those numbers as current.

> Kill-switch wording note: the WFP tests below are filter-API
> read-back (install real filters, read them back via
> `FwpmFilterGetById0`) and are `#[ignore]`d admin-required tests on
> Windows. Read-back proves the filters exist with the right
> parameters; it does NOT prove end-to-end leak protection (real
> traffic actually blocked when the tunnel drops). That is why
> README.md says the kill switch is "not verified on a real Windows
> machine" — the two statements describe different levels of testing,
> and both are true.

### Verified Test Suites & Windows API Integration Tests

1. **WFP Kill Switch & Dynamic Session (`tests/wfp_killswitch_test.rs`):**
   - `test_real_windows_wfp_filter_lifecycle_and_readback`: Installs real filters via `FwpmFilterAdd0` in a dynamic session and independently reads back filter IDs and universal sublayer bindings via `FwpmFilterGetById0`.
   - `test_real_windows_wfp_dynamic_session_automatic_reaping`: Proves BFE automatically reaps all filters when the dynamic session handle is closed.
   - `test_wfp_permit_rules_outrank_block_rules`: Proves permit rules (loopback 15, DHCP 14, edge 13, tunnel 12) strictly outrank block rules (0).
   - `test_wfp_killswitch_fault_injection_rolls_back_partial_rules`: Atomic rollback on partial failure.

2. **DNS & Tunneling (`tests/dns_tunnel_test.rs`):**
   - `test_real_windows_interface_dns_settings_readback`: Invokes native `SetInterfaceDnsSettings` with real adapter GUID and index, and verifies read-back via `GetInterfaceDnsSettings`.
   - `test_dns_cache_stores_and_retrieves_with_matching_txid`: Validates DNS wireformat caching and TxID remapping.
   - `test_dns_cache_expiration`: Validates TTL expiration.

3. **Netstack Correctness & Throughput (`tests/netstack_correctness_test.rs`):**
   - `test_netstack_out_of_order_packets_reassembly`: In-order delivery across out-of-order segment arrivals.
   - `test_netstack_overlapping_and_duplicated_segments`: Byte-trimming on overlapping segments without duplication.
   - `test_netstack_stream_transfer_checksum_verification`: Byte-for-byte integrity on 64 KiB streams.
   - `test_netstack_throughput_with_reordering_loss_and_checksum`: 32 KiB stream with swapped arrivals and simulated packet loss with SHA-256 verification.
   - `test_netstack_receiver_zero_window_persist_and_recovery`: Zero-window persist probe handling and recovery without reset.
   - `test_netstack_upstream_write_failure_sends_rst`: Immediate RST on upstream write failures (never ACKs lost data).
   - `test_netstack_5000_short_server_closed_flows_zero_residual`: Flow actor shutdown and immediate reaping.
   - `test_netstack_multi_flow_isolation`: Flow independence via `try_send`.

4. **Lifecycle & Cancellation (`tests/lifecycle_actor_test.rs`, `tests/actor_cancellation_test.rs`):**
   - `test_50_connect_disconnect_cycles_zero_task_leak_and_port_released`: Proves zero task leaks across 50 connect/disconnect cycles and immediate re-binding of proxy port 10800.
   - `test_reconnect_path_transitions_to_connected_and_ignores_stale_events`: Proves reconnect flow and immunity to stale events.
   - `test_cancel_during_reconnecting_preempts_immediately`: Preempts reconnect within 500ms.
   - `test_cancel_preempts_stalled_connecting_within_1_second`: Preempts stalled connects within 1s.

5. **Recovery Journal (`tests/recovery_journal_test.rs`):**
   - `test_recovery_journal_fault_injection_after_each_step`: Proves crash recovery for step 1, step 2, and ProxyOnly mode.
   - `test_recovery_journal_records_and_replays_dirty_state`: Startup recovery replays dirty routes and proxy backup.
   - `test_recovery_journal_clean_shutdown_removes_file`: Verifies journal removal on clean shutdown.

6. **Security & Packaging (`tests/security_packaging_test.rs`):**
   - `test_tampered_binary_is_strictly_refused`: Refuses modified executable.
   - `test_tampered_wintun_dll_refused`: Refuses tampered `wintun.dll`.
   - `test_tampered_webview2_loader_dll_refused`: Refuses tampered `WebView2Loader.dll`.
   - `test_safe_dll_search_and_single_instance`: Verifies `SetDefaultDllDirectories` and mutex.

7. **Token Provider & Crypto (`tests/fxa_token_provider_test.rs`, `tests/fxa_crypto_test.rs`):**
   - Verifies auto-refresh, token rotation persistence, 401 permanent error purging, transient fallback, and server revocation on sign-out.

---

## 2. Manual Verification Procedures (Windows Environment)

The following procedures verify features requiring live Windows kernel components (Wintun kernel driver, Windows Filtering Platform driver, IP Helper interface binding).

### Scenario 1: Clean Connection, Data Transfer & Disconnection (Scenario 1 & 10)
**Procedure:**
1. Launch iFoxy: `cargo run --release --bin ifoxy_app`
2. Sign in with Firefox Accounts.
3. Select server and click the Power button to connect.
4. Verify Wintun adapter is created:
   ```powershell
   Get-NetAdapter -Name "iFoxy"
   ```
   *Expected:* Interface Status: Up, LinkSpeed: 1 Gbps, MTU: 1420.
5. In a terminal, run a continuous curl transfer:
   ```powershell
   curl.exe -v https://cloudflare.com -o NUL
   ```
6. Click the Power button to disconnect.
7. Verify adapter is removed and port is released:
   ```powershell
   Get-NetAdapter -Name "iFoxy" -ErrorAction SilentlyContinue
   ```
   *Expected:* No adapter found; default routes intact.

### Scenario 2: WFP Kill Switch & Leak Verification (Scenario 6)
**Procedure:**
1. Start Wireshark on the physical network adapter (Ethernet/Wi-Fi).
2. Apply Wireshark capture filter: `not host <vpn_edge_ip> and not arp and not udp port 67 and not udp port 68`.
3. In iFoxy, connect with Kill Switch enabled.
4. Intentionally terminate the upstream tunnel connection (e.g., unplug cable or block edge port in router).
5. Attempt outbound web browsing (`curl.exe http://example.com`).
6. Observe Wireshark trace:
   *Expected Result:* Zero packets leave the physical adapter. All non-edge, non-DHCP transit packets are dropped by WFP filter `iFoxy_KillSwitch_Block_All_V4`.

### Scenario 3: Crash Recovery Journal Replay (Scenario 5)
**Procedure:**
1. Connect iFoxy in Full System mode.
2. Confirm the journal exists:
   ```powershell
   Get-Content "$env:LOCALAPPDATA\iFoxy\recovery_journal.json"
   ```
3. Forcefully kill the process from task manager:
   ```powershell
   Stop-Process -Name ifoxy_app -Force
   ```
4. Check routing table:
   ```powershell
   Get-NetRoute -DestinationPrefix "0.0.0.0/1" -ErrorAction SilentlyContinue
   ```
5. Relaunch iFoxy.
6. Observe logs:
   *Expected Result:* `[INFO] Replaying recovery journal: rolling back 2 routes and restoring proxy`. Route `0.0.0.0/1` is removed; normal network access is restored.

### Scenario 4: Hostile Local Process Token Isolation (Scenario 8)
**Procedure:**
1. Launch iFoxy.
2. From a separate PowerShell window (running as the same user):
   ```powershell
   Invoke-WebRequest -Uri "http://127.0.0.1:51820/" | Select-Object -ExpandProperty Content
   ```
   *Expected Result:* HTML contains zero bearer tokens or API keys.
3. Attempt to invoke the API without a token:
   ```powershell
   Invoke-RestMethod -Uri "http://127.0.0.1:51820/api/get_auth_state" -Method Post -Body "{}" -ContentType "application/json"
   ```
   *Expected Result:* HTTP 401 Unauthorized: `Missing or invalid X-iFoxy-Token`.


## Destructive and Windows-only tests

- `test_real_windows_interface_dns_settings_readback` (in `tests/dns_tunnel_test.rs`) changes the DNS of your real active adapter. It is `#[ignore]`d and also needs `IFOXY_DESTRUCTIVE_TESTS=1`:
  `$env:IFOXY_DESTRUCTIVE_TESTS=1; cargo test --test dns_tunnel_test -- --ignored`
  It restores the complete original state, but if a run is interrupted, reset manually with `Set-DnsClientServerAddress -InterfaceIndex <n> -ResetServerAddresses`.
- The WFP tests (`tests/wfp_killswitch_test.rs`) install real block-all filters for a few milliseconds and need an elevated shell. Run them from a local console, not over RDP/SSH.
- WFP read-back tests verify filter existence, layer, action, weight and condition values. They do **not** prove that packets are really blocked; use the packet-capture procedure above.
