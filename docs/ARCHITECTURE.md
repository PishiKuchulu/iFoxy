# iFoxy for Windows — Architecture Decision Record (ADR)

## 1. Tunnel Engine (C1)

### 1.1 TCP Flow Extraction and Bridge Architecture
- **Problem:** Wintun delivers raw Layer 3 IPv4 packets. Mozilla VPN's upstream infrastructure provides HTTP/2 CONNECT proxies. A Layer 3 to Layer 7 bridge is required to terminate client TCP flows from Wintun and multiplex them over HTTP/2 CONNECT streams via `H2UpstreamSession::open_stream`.
- **Selected Component:** Native Userspace TCP Virtual Stack (`VirtualNetstack`) implemented in Rust.
- **Alternatives Considered:**
  1. *External tun2socks C-Go binary/DLL:* Rejected due to process management complexity, packaging risks (C3), DLL loading vulnerabilities, and cross-runtime overhead.
  2. *smoltcp crate:* Highly capable but requires extensive no-std/static ring-buffer allocations that add complexity for dynamic stream multiplexing over async Tokio channels.
  3. *Native Rust Virtual TCP Engine:* Chosen and implemented in `src/vpn/netstack.rs`. Features a decoupled per-flow actor model (`TcpFlowActor`) where incoming packets from `PacketPump` are dispatched sequentially through bounded channels without holding any lock across `.await`. Implements RFC 793/1323 sequence wrapping arithmetic (`seq_before`, `seq_after`), full 3-way handshake simulation with clamped MSS option (1380 bytes), state tracking (`SynReceived` -> `Established` -> `CloseWait`/`FinWait1`/`FinWait2` -> `Closed`), out-of-order reassembly queue (`BTreeMap<u32, Vec<u8>>`), duplicate segment detection, overlapping segment trimming, downstream send buffer (`VecDeque<UnackedSegment>`) with 3-duplicate-ACK fast retransmit, periodic RTO timer (200ms) with peer-unresponsive RST fail-safe, window flow control, SYN deduplication, and graceful FIN half-close handling.
- **Memory & Concurrency Bounds:**
  - Max concurrent TCP flows: 4,096 hard cap (`MAX_FLOWS`).
  - Per-flow inbound reassembly queue cap: 256 KiB (`MAX_REASSEMBLY_BUF_PER_FLOW`).
  - Per-flow downstream in-flight buffer cap: 256 KiB (`MAX_IN_FLIGHT_BYTES_PER_FLOW`).
  - Zero global locks held across async `.await` boundaries (read/write locks on the flow table are microsecond-scoped for channel dispatching).
  - Idle timeout: 120s of flow inactivity automatically terminates and reaps the flow.

### 1.2 UDP, DNS, ICMP, and IPv6 Policies
- **DNS Policy:**
  - UDP port 53 packets captured on the Wintun adapter are parsed.
  - DNS queries are converted into TCP DNS wireformat (RFC 1035 length-prefixed) or DNS-over-HTTPS (DoH) requests and forwarded through the encrypted H2 tunnel to the VPN's upstream DNS resolver (or configured resolver).
  - Outbound DNS traffic on non-VPN interfaces is blocked via Windows Filtering Platform (WFP) to prevent DNS leaks.
- **Non-DNS UDP Policy:**
  - The Mozilla Guardian HTTP/2 CONNECT proxy only supports TCP streaming (`CONNECT <host>:<port>`).
  - All non-DNS UDP traffic received on Wintun is immediately rejected with an ICMP Destination Unreachable (Port Unreachable, Code 3) packet injected back into the Wintun receive queue. This prevents applications from hanging indefinitely.
- **ICMP Policy:**
  - Inbound ICMP Echo Requests (Ping) destined for the virtual adapter IP (`10.254.1.1`) are answered locally with ICMP Echo Replies to maintain network connectivity diagnostic tools (`ping 10.254.1.1`).
  - Transit ICMP Echo Requests are rejected with ICMP Destination Net Unreachable (Code 0) or dropped.
- **IPv6 Policy:**
  - As Mozilla HTTP/2 CONNECT upstream servers operate on IPv4 endpoints and the application routes IPv4 full-system traffic, IPv6 is blocked on physical interfaces during VPN connection using WFP filters and route metrics to avoid IPv6 leaks (H4).
  - IPv6 link-local and loopback traffic remains untouched.

### 1.3 MTU and MSS Planning
- **Wintun Adapter MTU:** Configured to `1420` bytes.
- **TCP MSS Clamping:** Max Segment Size is clamped to `1380` bytes (MTU 1420 - 20 bytes IPv4 header - 20 bytes TCP header).
- **Rationale:** Prevents fragmentation over the outer TLS/TCP/IP transport across the Fastly edge CDN.

---

## 2. Privilege Model (C3, M10, S-7)

### 2.1 Current Implementation (v0.1 Release)
- **Unified Elevated Application (`ifoxy_app.exe`):**
  - Runs with Administrator elevation requested at startup (`is_admin()`, `request_elevation()`) in order to manage Wintun adapter initialization, IP Helper routing entries, and WFP filtering sessions.
  - Safe DLL search is enforced at the entrypoint via `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`.
  - Single-instance enforcement is achieved via a named Win32 mutex `Global\iFoxy_SingleInstance_Mutex`.
  - Embedded binary integrity: `wintun.dll` and `WebView2Loader.dll` are SHA-256 verified at startup (defense in depth). The primary protection is the install-location policy: once elevated, the app asks for explicit confirmation (default No) when running from a folder outside `%ProgramFiles%` (see docs/SECURITY.md).
- **Embedded UI & Control API:**
  - WebView2 runs within the native Win32 window (via `tao` and `wry`).
  - Internal control server binds to a dynamic loopback port on `127.0.0.1`.
  - A cryptographically random 256-bit token is generated at startup and delivered strictly out-of-band into the JavaScript runtime via `wry::WebViewBuilder::with_initialization_script(format!("window.__IFOXY_TOKEN__ = '{}';", token))`.
  - The control API enforces strict `Host: 127.0.0.1:<port>` checking, cross-origin rejection (`Origin` must match loopback), payload size caps (64 KiB), and constant-time token comparison (`subtle::ConstantTimeEq`).

### 2.2 Architectural Roadmap: Unelevated UI / Windows Service Split
- **Future Separation Target:**
  - Split into an unelevated UI client (`ifoxy_ui.exe`, Medium integrity) and an elevated background Windows service (`ifoxy_service.exe`, LocalSystem).
  - Inter-process communication via Windows Named Pipe (`\\.\pipe\iFoxyControl`) with restrictive DACL granting access solely to the interactive user SID and Administrators.

---

## 3. State Machine (M2, C5, C6)

### 3.1 Single Owner Actor
- A single Tokio actor task owns all state transitions.
- External callers (UI IPC, Watchdog, Network monitors) send commands via an `mpsc::Sender<VpnCommand>`.
- State updates are broadcast continuously via a `tokio::sync::watch::Sender<VpnState>`.

### 3.2 Command Set
- `Connect { target: ProxyCandidate, token_provider: Arc<dyn TokenProvider> }`
- `Cancel`
- `Disconnect`
- `NetworkChanged { default_gw: Ipv4Addr }`
- `TokenRefreshed { new_token: String }`

### 3.3 State Transition Table
| Current State | Command / Event | Next State | Action / Side Effect |
|---|---|---|---|
| `Disconnected` | `Connect` | `Connecting` | Start DNS resolution, TLS handshake, Wintun setup |
| `Connecting` | Handshake OK & Route OK | `Connected(mode)` | Enable packet pump / proxy, start keepalive & renewal |
| `Connecting` | Handshake Error / Route Error | `Failed(error)` -> `Disconnected` | Rollback all partial state in reverse order |
| `Connecting` | `Cancel` | `Disconnecting` -> `Disconnected` | Signal CancellationToken, abort in-flight connect |
| `Connected` | `Disconnect` | `Disconnecting` | Stop pump, revert routes, revert proxy, close H2 |
| `Connected` | H2 Drop / Keepalive Timeout | `Reconnecting` | Exponential backoff reconnect, notify UI |
| `Reconnecting` | Reconnect Success | `Connected` | Resume streams with fresh token |
| `Reconnecting` | Max Retries Exceeded / Disconnect | `Failed` / `Disconnected` | Trigger clean shutdown |
| `*` | Service Stop / Fatal Panic | `Disconnected` | Replay recovery journal, revert network |

### 3.4 Cancellation Propagation (C5)
- Every connection phase is tied to a hierarchical `tokio_util::sync::CancellationToken`.
- On `Cancel` or `Disconnect`, the token is cancelled immediately.
- Background tasks (packet pump, watchdog, local proxy) join within a bounded 3-second grace period before being aborted.

---

## 4. Network Control & Safety (M4, H3, H4, H5)

### 4.1 Native Windows API vs Shell Commands (M4)
- **Elimination of Shell Commands:** All invocations of `route.exe`, `netsh.exe`, `reg.exe`, and `powershell.exe` are completely removed.
- **IP Helper API (`iphlpapi.dll`):**
  - Route installation & deletion: `CreateIpForwardEntry2`, `DeleteIpForwardEntry2`.
  - Default gateway & adapter discovery: `GetBestRoute2`, `GetAdaptersAddresses`.
  - Interface metric & DNS assignment: `SetInterfaceDnsSettings`, `SetIpInterfaceEntry`.
- **Abstraction:** All network interactions are defined through a `NetworkBackend` trait, enabling 100% unit testing with an in-memory `MockNetworkBackend`.

### 4.2 Windows System Proxy Guard (H3)
- Used strictly in `ProxyOnly` mode or when explicitly enabled by user.
- Pre-connection registry values are read directly via `Advapi32` (`RegOpenKeyExW`, `RegQueryValueExW`) and stored in memory and journal.
- Modified settings are applied in the user's registry hive and activated with `InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, ...)`.
- On exit, disconnect, or crash recovery, the exact saved configuration (PAC URL, bypass lists, manual servers) is restored.

### 4.3 Leaks, IPv6 & WFP Kill Switch (H4)
- **Windows Filtering Platform (WFP) Provider & Sublayer:**
  - Registered under GUID `IFOXY_WFP_PROVIDER_GUID`.
  - Sublayer configured with high weight to intercept outgoing traffic.
- **Kill-Switch Filter Set:**
  1. *Permit Local Loopback:* `127.0.0.0/8` and `::1`.
  2. *Permit VPN Tunnel Endpoint:* Outbound TCP traffic to the exact resolved edge `SocketAddr`.
  3. *Permit DHCP & Local Subnet:* Broadcast/multicast for local link maintenance.
  4. *Permit Wintun Interface:* All outbound traffic on the Wintun adapter index.
  5. *Block All Other Outbound IPv4 & IPv6:* Default block rule applied when kill switch is enabled.
- **Teardown Safety:** All WFP filters are dynamic and tied to the service session handle (`FWPM_SESSION_FLAG_DYNAMIC`), guaranteeing automatic kernel cleanup even on abnormal process termination.

### 4.4 Crash Recovery Journal (H5)
- **Journal Location:** `%LOCALAPPDATA%\iFoxy\recovery_journal.json` (or service equivalent in `%ProgramData%`).
- **Format:** Structured JSON array of executed operations with timestamps:
  - `RouteAdded { destination, prefix, gateway, if_index }`
  - `ProxyModified { original_enable, original_server, original_pac }`
  - `DnsModified { if_index, original_servers }`
  - `WfpInstalled { sublayer_id, filter_ids }`
- **Replay Policy:**
  - Written and flushed to disk before executing each network modification.
  - On application startup, the journal is inspected. If uncommitted operations exist, rollback is executed in reverse order before initializing new state.
  - Successfully unrolled journals are removed.

---

## 5. Secrets Management (C7, H1)

### 5.1 Storage & Encryption
- **Storage Technology:** Windows Data Protection API (DPAPI via `CryptProtectData` / `CryptUnprotectData`).
- **Scope:** `CRYPTPROTECT_UI_FORBIDDEN`.
- **Entropy:** Unique per-machine salt combined with application GUID.
- **File Permissions:** Owner-only ACL (`SetNamedSecurityInfoW` allowing only the current user or SYSTEM).

### 5.2 Token Storage Matrix
| Credential | Persisted to Disk? | Encryption | Memory Protection |
|---|---|---|---|
| User Password | **NEVER** | N/A | Zeroized immediately after KDF derivation |
| `authPW` (Intermediate) | **NEVER** | N/A | Zeroized immediately after login request |
| FxA Session Token | **NEVER** | N/A | Discarded after OAuth exchange |
| OAuth Refresh Token | **YES** | DPAPI Protected | `Zeroizing<String>` in memory |
| OAuth Access Token | **YES** | DPAPI Protected | Refreshed automatically when within 5m of expiry |
| Proxy Pass JWT | In Memory Only | Plaintext in RAM | Zeroized on disconnect |

### 5.3 Revocation & Sign-out
- On user sign-out (`logout`), the app sends a revocation request to Mozilla FxA (`POST /oauth/destroy`).
- The DPAPI-encrypted session file is securely overwritten with zeros before deletion.

---

## 6. Crypto Provider & Dependencies (H6, L1)

### 6.1 Single Crypto Provider Selection
- **Selected Provider:** `ring`.
- **Rationale:** Mozilla Accounts KDF (PBKDF2-HMAC-SHA256, HKDF) and Hawk authentication (HMAC-SHA256) natively utilize `ring` or standard SHA2 crates. `ring` has proven stability, avoids MSVC C++ CMake toolchain dependencies of `aws-lc-sys`, and compiles reliably across both GNU and MSVC targets.
- **Cargo Feature Configuration:**
  - `rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12"] }`
  - `tokio-rustls = { version = "0.26", default-features = false, features = ["ring"] }`
  - `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls-manual-roots", "json", "cookies"] }`
  - Explicit global initialization in `main()`: `rustls::crypto::ring::default_provider().install_default().ok();`
- **Verification:** `cargo tree -i aws-lc-rs` returns empty. Only `ring` exists in `cargo tree`.
