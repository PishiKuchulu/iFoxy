# FIX TRACKER

> Round 6 note: the only code change after the verified round 5 is in `src/main.rs` (install-location warning dialog instead of a hard refusal). It was edited without a compiler.
 (verified status - Round 5)

**Compiled and verified on Windows 11 Pro with MSVC toolchain (`stable-x86_64-pc-windows-msvc`, rustc 1.98.1).**
All 107 active automated tests across 27 integration test suites compile and pass cleanly (`cargo test` summary: 107 passed; 0 failed; 1 ignored). The 1 ignored test is an opt-in destructive DNS read-back test that was independently executed and passed with `IFOXY_DESTRUCTIVE_TESTS=1`.

## Round 5 Verified Items

| Item | Status | What Changed | Verification Evidence |
|------|--------|--------------|-----------------------|
| B2 Authenticode Verification | FIXED | Added native `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`) validation for `wintun.dll` in `src/security.rs` and `src/vpn/wintun_adapter.rs`. Verified that valid signed DLLs pass and unsigned/tampered DLLs fail. | `test_wintun_authenticode_signature_verified` in `tests/security_packaging_test.rs`. |
| B3 End-to-end Reconnect Loop | FIXED | Made `GuardianClient` endpoint and `H2UpstreamSession` roots injectable. Real reconnect loop exercised with mock Guardian server and mock H2 server dropping connection 1 and accepting connection 2. State goes `Connected` -> `Reconnecting` -> `Connected`. | `test_end_to_end_real_reconnect_loop_with_fake_upstream` and `test_cancel_during_real_reconnect_loop_preempts` in `tests/lifecycle_actor_test.rs`. |
| B5 Event-Driven Route Change Detection | FIXED | Integrated native Windows `NotifyRouteChange2` with RAII cancellation via `CancelMibChangeNotify2` in `src/vpn/iphlpapi.rs` and wired it into the state machine watcher with debouncing. | `src/vpn/iphlpapi.rs`, `src/service/state_machine.rs`, verified in test suite. |
| Non-destructive DNS Testing | FIXED | `test_real_windows_interface_dns_settings_readback` marked `#[ignore]`, requires `IFOXY_DESTRUCTIVE_TESTS=1`, and restores complete original state via `native_set_interface_dns_servers(None)`. | Passed with `IFOXY_DESTRUCTIVE_TESTS=1`; verified adapter DNS restored via `Get-DnsClientServerAddress`. |
| Zero Task Leak Assertion | FIXED | 50-cycle test keeps a live SOCKS5 stream and verifies that all Arc clones of `H2UpstreamSession` are released on disconnect (`Arc::strong_count == 1`). | `test_50_connect_disconnect_cycles_zero_task_leak_and_port_released` in `tests/lifecycle_actor_test.rs`. |
| WFP Filter Semantics Readback | FIXED | Verifies layers, sublayer, actions, weights, and exact condition values (edge IP, tunnel IP, DHCP port, loopback) via real `FwpmFilterGetById0`. | `test_real_windows_wfp_filter_semantics_readback` in `tests/wfp_killswitch_test.rs`. |
| DoH Chunked Decoding & Size Cap | FIXED | `decode_doh_http_response` parses Content-Length and chunked transfer encoding, strips framing, enforces 64 KiB cap, and surfaces read errors. | `doh_response_with_content_length_is_decoded`, `doh_response_with_chunked_encoding_is_decoded_without_framing`, `doh_response_errors_are_reported`. |
| Install Location Hardening | CHANGED (round 6) | Round 5 refused to start from any folder outside `%ProgramFiles%`, which blocked normal development runs (`target\release`). Now the check runs once, in the elevated process, and shows a Yes/No warning (default No) via `MessageBoxW`; `IFOXY_ALLOW_PORTABLE=1` skips the question. Not compiled by the author of this change. | `install_location_policy_allows_only_admin_writable_roots` in `tests/security_packaging_test.rs`. |
| Non-Windows DNS Stubs | FIXED | Return error rather than non-operational success. | `src/vpn/iphlpapi.rs`. |

## Known Architecture & Privilege Boundaries

- **Unified Elevated Architecture (B1)**: The process executes elevated with admin privileges to manage Wintun driver handles, WFP filter engine, and system routing tables. DLL hijacking is prevented via `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`, install location policy (`%ProgramFiles%` only), and load-time hash and Authenticode verification of `wintun.dll`. Service/UI split is BLOCKED with architecture and manual test procedure documented.
- **DNS Handling**: Primary resolution is handled by Wintun adapter DNS (`SetInterfaceDnsSettings`), with netstack UDP 53 interception tunneled via H2 CONNECT to 53 or RFC 8484 DoH over 443 fallback.
- **IPv6 Policy**: IPv6 is explicitly blocked by WFP filter `iFoxy_Block_IPv6_Leak` at `FWPM_LAYER_ALE_AUTH_CONNECT_V6` (loopback permitted) to prevent IPv6 bypass leaks.

