# Round 4 changes and what you must verify

Written WITHOUT a compiler or a Windows machine. First steps on your side:

1. `cargo build` (MSVC toolchain). If it fails, the most likely place is `src/vpn/killswitch.rs`, module `wfp`: the anonymous-union field name `.Anonymous` and some `FWP_*`/`FWPM_*` constant or type names depend on your `windows-sys` version. Send me the compiler errors and I will fix them.
2. `cargo test`. Record the real summary line.
3. On Windows, as Administrator, connect in Full mode and check:
   - `netsh wfp show filters` (or `FwpmFilterEnum0`) lists the `iFoxy_KillSwitch_*` filters while connected and none after disconnect or after killing the process.
   - With the tunnel killed, a packet capture on the physical adapter shows only edge-bound traffic.
   - Kill the upstream connection once: state goes `Reconnecting` then `Connected`.
   - `Get-DnsClientServerAddress` shows 1.1.1.1 on the iFoxy adapter.
   - Unplug/replug the network: the app reconnects within ~15 s.

See `docs/FIX_TRACKER.md` for per-item status and the list of things NOT done.
