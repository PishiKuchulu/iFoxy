# iFoxy for Windows — Threat Model & Security Architecture

## 1. Threat Model & Boundaries

iFoxy runs on Windows as a native client providing Layer 3 transit tunneling and local proxying over HTTP/2 CONNECT. The threat model considers the following threat actors:

1. **Malicious Local Process (Standard User):**
   - Attempts to sniff loopback traffic or extract credentials.
   - Attempts to send unauthenticated commands to the VPN control interface.
   - Attempts to hijack DLL search paths or tamper with binaries.
2. **Untrusted Web Page in WebView2:**
   - Attempts cross-site scripting (XSS) or cross-origin requests to control the VPN or access tokens.
3. **Network Adversary (Passive / Active):**
   - Attempts to inspect transit traffic, inject malicious certificates, or exploit DNS/IPv6 leaks.
4. **Local Attacker with Filesystem Access:**
   - Attempts to read cached tokens or recovery state from disk.

---

## 2. Security Mitigations

### 2.1 Out-of-Band Control Token Delivery (C2, R-10)
- **Problem:** Serving authentication tokens via HTTP `GET /` or embedding them in `<meta>` tags enables any local process running as the same user to sniff the token with a simple HTTP GET request to `127.0.0.1`.
- **Mitigation:**
  - The localhost HTTP listener (`control_api.rs`) serves only static, token-free HTML/CSS/JS.
  - The cryptographic 256-bit bearer token is generated at startup and delivered **out-of-band** directly into the WebView2 execution environment via `wry::WebViewBuilder::with_initialization_script("window.__IFOXY_TOKEN__ = '...';")`.
  - HTTP requests to `/` and `/index.html` contain zero sensitive credentials.
  - All control API mutations require the `X-iFoxy-Token` header, validated using constant-time comparison (`subtle::ConstantTimeEq`).
  - Requests with missing or invalid tokens are rejected with HTTP 401 Unauthorized.
  - Strict Content-Security-Policy (CSP) headers block all third-party origins.

### 2.2 Process Privilege Separation & Single-Instance Handover (C3, M10, R-14)
- **Privilege model (corrected 2026-10-25 — the previous "medium
  integrity UI" line was stale):** there is NO privilege separation in
  the current build. The unelevated launcher re-launches the process
  elevated (`ShellExecuteW("runas")` on Windows, pkexec on Linux) and
  exits; the elevated process then runs everything — WebView2 UI,
  control server, VPN core, Wintun/routing/WFP. Administrative tasks
  (Wintun adapter installation, IP Helper routing, WFP firewall rules)
  therefore run in the same process as the UI. An unelevated-UI +
  hardened privileged-service split is documented as blocked/future
  work, not implemented (see §2.3 "Not done" and
  docs/FIX_TRACKER.md).
- **Mutex Handover Safety (R-14):**
  - Checking `is_admin()` occurs **before** attempting to acquire the single-instance mutex.
  - When unelevated, the process invokes `ShellExecuteW("runas")` and immediately terminates (`std::process::exit(0)`).
  - Only the elevated child process acquires `IFOXY_APP_MUTEX`, preventing `ERROR_ALREADY_EXISTS` deadlocks and race conditions.

### 2.3 Binary & DLL Integrity Verification (C3, R-11)
- **Safe DLL Search Order:**
  - `enforce_safe_dll_search()` calls Win32 `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` immediately upon startup, neutralizing DLL preloading / search-order hijacking from the application directory or `%TEMP%`.
- **Wintun & WebView2Loader Cryptographic Integrity:**
  - `wintun.dll` search paths strictly exclude untrusted directories, and `wintun.dll` is verified against its SHA-256 digest (`e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`) before loading.
  - The WebView2 loader is **statically linked** (`WebView2LoaderStatic.lib`, from the official Microsoft WebView2 SDK) — there is no `WebView2Loader.dll` in the product anymore. Both vendored binaries are committed to the repository with recorded provenance: `wintun.dll` (WireGuard LLC, digest above) and `WebView2LoaderStatic.lib` (Microsoft WebView2 SDK, SHA-256 `89c6b872783b8f6c3cedbff618adb42082d455c615453ae10cfc753f1e8f25d8`).
  - If a stray `WebView2Loader.dll` nevertheless appears next to the executable, it is still verified against its known digest (`86545b66cdb0603bc26b626fb9ad610cb6e71f28d468f5ea66df23b03dda96d5`) at startup and rejected on mismatch. **This is defense in depth only**: a DLL loaded as an import is loaded by the OS before `main` runs, and a hash check followed by a later load is a check-then-use race.
  - **Install location policy (the real protection):** once elevated, the application asks for explicit confirmation (default No) unless its folder is under `%ProgramFiles%` (administrator-writable only). Development or portable use means answering Yes or setting `IFOXY_ALLOW_PORTABLE=1`. The question is shown by the elevated process only, once per run. A non-admin attacker cannot replace files inside Program Files, which closes both the DLL-planting and the executable-replacement paths. Use `install.ps1` to install with an admin-only ACL.
  - **Not done:** the whole process, including the WebView2 engine, still runs elevated (no unelevated UI + elevated service split), and there is no Authenticode verification.

### 2.4 Secrets Protection & Server Revocation (C7, H1, R-16)
- **At-Rest Protection:**
  - Session tokens and credentials are encrypted using the Windows Data Protection API (DPAPI via `CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN` and custom application entropy).
  - Plaintext tokens are never written to disk.
- **In-Memory Hygiene:**
  - Credential structures implement `Zeroize` and `ZeroizeOnDrop`, wiping cryptographic material from memory upon deallocation.
- **Server Revocation on Sign-Out:**
  - When the user signs out (`logout`), `FxaTokenProvider::sign_out()` invokes `FxaClient::revoke_token()` against Mozilla's `/oauth/destroy` endpoint for both access and refresh tokens before zeroing and unlinking local storage.

### 2.5 Leak Prevention & Dynamic WFP Kill Switch (H4, R-8)
- **Dynamic WFP Session:**
  - Firewall filters are created under a dynamic WFP session (`FWPM_SESSION_FLAG_DYNAMIC`).
  - If the application crashes, the Windows kernel automatically unregisters and tears down all filters.
- **Rule Hierarchy (Weighting):**
  - Loopback Permit: Weight 15 (Highest)
  - DHCP Permit: Weight 14
  - Upstream Edge Endpoint Permit: Weight 13
  - Wintun Virtual Adapter Permit: Weight 12
  - Block All Outbound IPv4: Weight 0 (Default block)
- **IPv6 Leak Prevention:**
  - IPv6 outbound traffic is blocked on non-loopback interfaces when the tunnel is active.

### 2.6 Crash Recovery Journaling (H5, R-9)
- **Pre-Mutation Disk Flush:**
  - Every network modification (route addition, proxy change, WFP filter) is serialized to `%APPDATA%\iFoxy\recovery_journal.json` and flushed to disk **prior** to executing the system API call.
- **Startup Replay:**
  - On process initialization, `RecoveryJournal::recover_if_dirty()` checks for uncommitted journal entries from prior crashes and rolls them back in reverse order before initializing the VPN service.

### 2.7 Single Unified Crypto Provider (H6)
- The entire crate and its dependency tree rely solely on `ring` (`0 aws-lc-rs`).
- `webpki-roots` provides the Mozilla root CA certificate store for TLS validation across all HTTP clients.
