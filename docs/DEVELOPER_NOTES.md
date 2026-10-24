# iFoxy for Windows (Desktop Client)

Native Windows desktop client for iFoxy implemented in **Rust** with native WebView2 GUI, userspace virtual netstack Layer 3 tunneling, and HTTP/2 CONNECT upstream transport.

## Architecture & Features

- **Native Desktop GUI**: Window management via Win32 `tao` and Microsoft Edge WebView2 via `wry`, styled with custom CSS and vanilla JavaScript without external web frameworks.
- **Hardened Control API (`control_api.rs`)**: Loopback API authenticated via per-session cryptographic bearer tokens (`X-iFoxy-Token`) delivered out-of-band to WebView2 (`window.__IFOXY_TOKEN__`), strict Host header validation, cross-origin blocking (403 Forbidden), 64 KiB payload limits, 5s request timeouts, and Content-Security-Policy (CSP) headers.
- **Tunneling Modes**:
  - **ProxyOnly (Safe Default)**: Local proxy listener with system WinINet proxy configuration, bypassing virtual adapter requirement.
  - **Full System (Wintun L3)**: Wintun kernel adapter capturing IPv4 transit traffic with clamped MTU 1420.
- **Virtual Userspace TCP Stack (`vpn/netstack.rs` & `vpn/packet_pump.rs`)**:
  - Per-flow actor tasks (`TcpFlowActor`), bounded inbound queue, `BTreeMap` reassembly queue, duplicate/overlapping segment trimming, fast retransmit, window tracking, SYN deduplication, FIN half-close.
  - Multiplexed over encrypted HTTP/2 CONNECT streams via Fastly edge infrastructure.
- **Supported Traffic & Limitations**:
  - **Supported**: IPv4 TCP streams and DNS queries (UDP 53 tunneled over encrypted streams with TTL caching).
  - **Limitations**: Non-DNS UDP traffic (e.g., VoIP, gaming, WebRTC) is not supported over HTTP/2 CONNECT and is safely rejected with ICMP Port Unreachable. IPv6 transit traffic is blocked on physical interfaces to prevent IPv6 leaks.
- **Leak Protection & Kill Switch (`vpn/killswitch.rs`)** — **implemented but NOT yet verified on Windows**:
  - WFP dynamic session with real `FwpmFilterAdd0` filters at the ALE connect layers: Permit loopback (15) > DHCP (14) > Edge (13) > Tunnel local address (12) > Block all (0); IPv6 is blocked except loopback. A failed install fails the connect.
  - The code was written without a compiler or Windows machine available. Build it, then verify with `FwpmFilterEnum0` / `netsh wfp show filters` and a packet capture (see docs/TESTING.md) before trusting it.
- **Windows network APIs (`vpn/iphlpapi.rs` & `vpn/registry.rs`)** (routes use IP Helper; adapter IP/MTU/DNS are applied through IP Helper and the registry):
  - Default gateway detection and route installation via Windows IP Helper API (`iphlpapi.dll`).
  - System proxy configuration with backup and restoration via Windows Registry APIs (`advapi32.dll`) and `InternetSetOptionW`.
- **Crash Recovery Journal (`vpn/recovery_journal.rs`)**: Persistent disk state journaling in `%APPDATA%\iFoxy\recovery_journal.json` with automatic startup replay to restore routes and proxy settings after unexpected termination.
- **Cryptographic Security & Secrets (`auth/secret_storage.rs` & `crypto/`)**:
  - Native Windows Data Protection API (DPAPI via `CryptProtectData`/`CryptUnprotectData`) with user-entropy salt. Plaintext credentials are never written to disk.
  - In-memory `ZeroizeOnDrop` token hygiene.
  - FxA PBKDF2/HKDF key derivation and Hawk HMAC-SHA256 authentication with server clock skew compensation (`crypto/hawk.rs`).
  - Single crypto provider enforced: `ring` (0 aws-lc-rs duplicates).
- **Audit Logging (`logging.rs`)**: Size-based rolling file appender with automatic regex redaction of bearer tokens, passwords, Hawk MACs, and session secrets.

## Project Structure

```
ifoxy/
├── src/
│   ├── main.rs              # Native GUI entrypoint, mutex guard & event loop
│   ├── security.rs          # Safe DLL search order & SHA-256 binary validation
│   ├── control_api.rs       # Hardened localhost HTTP control API
│   ├── logging.rs           # Rolling file logger with sensitive redaction
│   ├── tauri_bridge.rs      # App state coordinator & embedded UI assets
│   ├── auth/                # FxA client, token provider & DPAPI secret storage
│   ├── crypto/              # FxA KDF, Hawk HMAC & clock skew compensation
│   ├── guardian/            # Guardian API client & Challenge solver
│   ├── servers/             # Server list discovery, latency probing & failover
│   ├── service/             # State machine actor, supervisor & token watchdog
│   ├── tunnel/              # HTTP/2 multiplexed streams, flow control & metrics
│   └── vpn/                 # Wintun TUN, Netstack, IP Helper, Registry & WFP Kill Switch
├── ui/                      # Frontend (HTML5/CSS3/Vanilla JS)
│   └── assets/              # Brand PNGs: ifoxy_logo (icon), ifoxy_splash
│                          # (startup screen), ifoxy_banner (titlebar),
│                          # ifoxy_wordmark (login)
├── assets/                  # Windows resources: ifoxy.ico (exe/taskbar icon),
│                          # ifoxy_icon_32_rgba.bin (window icon for tao)
├── tests/                   # Integration and unit tests
├── Cargo.toml               # Rust dependencies and targets
├── build.rs                 # winres embeds ifoxy.ico + version info into exe
├── WebView2Loader.dll       # Microsoft WebView2 loader library
└── wintun.dll               # WireGuard Wintun x64 driver (hash verified)
```

## How to Build & Test

### Toolchain:
Use the MSVC toolchain (`rustup default stable-x86_64-pc-windows-msvc`, requires Visual Studio C++ Build Tools). No target is forced in the repository.

### Running Tests:
```powershell
cargo test
```

### Building and installing:
```powershell
.\build-release.ps1          # builds and collects files into .\dist
.\install.ps1                # (elevated) installs to %ProgramFiles%\iFoxy with an admin-only ACL
```
When started from a folder outside `%ProgramFiles%`, the elevated app shows a warning and asks **Run from this folder anyway? (default: No)**, because it runs elevated and loads DLLs from its own directory. For development, choose Yes or set `IFOXY_ALLOW_PORTABLE=1` (PowerShell: `$env:IFOXY_ALLOW_PORTABLE=1`) to skip the question.

## Status and known limitations

This project is **not production-ready**. See `docs/FIX_TRACKER.md` for the honest per-item status. Highlights:
- Never compiled or run by the author of the latest changes: expect compile fixes, especially in `vpn/killswitch.rs` (Windows Filtering Platform bindings).
- The whole application, including the WebView2 engine, still runs elevated; the planned split into an unelevated UI and an elevated service has **not** been done.
- DNS over the tunnel relies on the upstream accepting CONNECT to port 53; this is unverified.
- Plain `http://` through the system proxy is rejected (use HTTPS or Full mode).
- This is an unofficial third-party client. It reuses identifiers of official Mozilla clients and a bot-challenge solver; those parts are fragile, can be blocked at any time, and may violate service terms.
