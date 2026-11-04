# Changelog — iFoxy desktop (Windows & Linux)

## v1.0.30 combined release - Android disconnect crash fix

Android-focused fix (desktop unchanged, still 0.2.3): disconnecting
could crash the app — the Home session timer dereferenced the
connection start time with `!!` inside its loop while disconnect
nulls it. The timer now captures the start time up front. Crash
reports record the app version, and the release workflow keeps
the R8 mapping as an artifact so future crash traces can be read.

Android 1.0.30 (versionCode 67): see android/CHANGELOG.md.
Supersedes v1.0.29.

## v1.0.29 combined release - Android updater honesty fix

Android-only fix (desktop unchanged, still 0.2.3): the in-app
updater no longer reports "You're up to date" when the update
check fails at the HTTP level — a GitHub rate-limit 403 on a
shared VPN egress IP hid the v1.0.28 release from 1.0.27 phones.
A failed check now surfaces as a failure with its status code.

Android 1.0.29 (versionCode 66): see android/CHANGELOG.md.
Supersedes v1.0.28.

## v1.0.28 combined release - UI/UX audit fix wave (both platforms)

Desktop (still 0.2.3) changes from the UI/UX audit of 1.0.27:

- Light theme is now a first-class citizen: all connection-state
  colors, the latency badge, the login error banner, the sign-out
  button and the subscription badge have dark-on-light values that
  meet WCAG AA (previously as low as 1.5:1).
- Changing location while connected now reconnects the tunnel to
  the new location (Android parity) instead of showing the new
  location as if it were active.
- Accessibility: drawers trap focus; native buttons and the
  tunnel-mode select have visible focus; server rows are real
  listbox options with aria-selected; the tunnel-mode select's
  styling no longer references undefined CSS variables.
- Server list shows a loading state; copy feedback appears only
  when the copy actually succeeds; clearing logs asks first; a
  failed entitlement fetch shows "Subscription unknown"; if the
  local service stops answering mid-session the UI says so after
  three failed polls instead of freezing on "Connected".
- Login uses real forms (native submit + email validation with
  per-field error state); a Text & UI size setting (100/115/130%)
  was added; reduced-motion preference is honored; the connected
  home view is compacted to fit the window; disconnected speed and
  latency readouts show "—" instead of fake zeros.

Android 1.0.28 (versionCode 65): see android/CHANGELOG.md.
Supersedes v1.0.27.

## v1.0.27 combined release - granular-audit fix wave (both platforms)

Desktop (still 0.2.3) changes from the same audit as Android 1.0.27:

- The Logs drawer now shows the real backend log (the `get_logs`
  bridge command existed but was never called); hardcoded seed lines
  removed; Copy and Clear buttons added.
- Power button: an in-flight guard ends the connect/cancel race
  with the 1-second status poll; the two 1-second status loops are
  merged into one.
- Settings honesty: the subscription badge is driven by the real
  entitlement; the DNS row is labelled as built-in Cloudflare info;
  tunnel mode and theme now persist across restarts; kill-switch
  status in Full mode is disclosed; logout failures are no longer
  silently ignored.
- Home: session totals + duration row; the local proxy endpoint
  (127.0.0.1:10800) is shown and copyable in Proxy Only mode; the
  latency badge now shows the connected node's probed latency.
- Server list: a failed fetch shows an error + Retry instead of
  invented fallback locations; the current selection is marked;
  search is debounced; the list loads on session resume.
- Accessibility: keyboard operation for the power button, location
  card and server rows; dialog semantics, Escape/backdrop close and
  focus management for drawers; live regions for status and errors;
  contrast fixes (button text, tertiary text, badges, error banner).
- The invented-fallback and dead-code cleanups: FALLBACK_SERVERS
  removed; token meta fallback removed; baked-in CSP aligned with
  the served policy; account emails masked in UI log lines.

Deferred with reasons: browser-based sign-in for desktop (the
Android 406 fix) remains a separate project — desktop API sign-in
exposure is still unverified; DNS/MTU stay engine-fixed values
this wave (now disclosed in the UI); no desktop updater or
multi-account vault yet (feature parity, not defects).

Android 1.0.27 (versionCode 64): see android/CHANGELOG.md.
Supersedes v1.0.26.

## v1.0.26 combined release - in-page token exchange (desktop unchanged)

The desktop code is unchanged in this release (still 0.2.3). Android
1.0.26 (versionCode 63) runs the post-sign-in token exchange inside the
signed-in browser page (native exchange kept as fallback) and improves
406 diagnostics in the in-app log. Supersedes v1.0.25.

## v1.0.25 combined release - signed-out Settings/Logs access (desktop unchanged)

The desktop code is unchanged in this release (still 0.2.3). Android
1.0.25 (versionCode 62) lets a signed-out user reach Settings and Logs
from the sign-in screen, so a broken sign-in no longer locks diagnostics
away. Supersedes v1.0.24.

## v1.0.24 combined release — Android 406 solver fix (desktop unchanged)

The desktop code is unchanged in this release (still 0.2.3). Android
1.0.24 (versionCode 61) fixes sign-in completion on networks where
Mozilla's bot protection still blocked the token exchange after the
in-app browser sign-in: the challenge solver now solves the served 406
challenge. Supersedes v1.0.23.

## v1.0.23 combined release — Android sign-in fix (desktop unchanged)

The desktop code is unchanged in this release (still 0.2.3). The
combined v1.0.23 tag exists for the Android client, whose direct
API sign-in is blocked by Mozilla's bot protection (HTTP 406);
Android 1.0.23 moves sign-in to Mozilla's official page inside the
app. See android/CHANGELOG.md. This release supersedes the partial
v1.0.22 release (whose Windows asset never published).

## 0.2.3 — Third external-review wave

Fixes from a third full external code review, this time of the
v1.0.21 tree. As before, every finding was re-verified against the
source before being acted on. The review was largely accurate;
corrections worth recording: the docs-count finding (L-20) was
already fixed in wave 2 and quoted stale text; the README version
mentions it flagged (DOC-1) are historical "since v1.0.8" markers,
not a stale current version; the Android widget finding (A-3)
missed the per-install guard token that already gates the exported
receiver; and one C-2 citation pointed at unrelated routing code
(the real elevated write was in the recovery journal). Several
Low-severity items were verified in aggregate rather than line by
line; where a claim did not hold up it is listed as not acted on.

- **Crash recovery no longer fails open (C-1).** Restores whose
  failure leaves the machine broken — system proxy, recorded
  kill-switch filters, resolv.conf — are now hard failures:
  `recover_if_dirty` returns `RecoveryIncomplete`, the journal file
  is KEPT so the next start retries, and startup refuses (the
  parse-error path was already fatal since wave 2). Route deletions
  stay best-effort with loud logging, and on Linux a best-effort
  sweep removes a stale iptables chain even when the journal
  recorded no filters.
- **Journal-supplied resolv.conf is validated before the elevated
  write (C-2).** The recovery journal lives in a user-writable
  directory, so its recorded `/etc/resolv.conf` contents are now
  checked line by line (only `nameserver <IP>`, `search`, `domain`,
  `options`, `sortlist`, comments and blanks; 64 KiB cap) before
  the root process writes them back. Invalid content fails
  recovery instead of being installed.
- **System tools are invoked by absolute path (C-3).** A new
  `syscmd` module resolves `ip`, `iptables`-adjacent helpers,
  `pkexec`, `gsettings`, `netsh` and friends under System32 /
  /usr/sbin / /sbin / /usr/bin instead of trusting the elevated
  process's PATH. Two residuals are by design and documented in
  docs/SECURITY.md §2.8: the elevated process keeps state in the
  user's home (that is where the FxA session lives), and the
  pkexec environment passthrough is deliberate (the desktop
  session variables are required for the GUI to appear).
- **Logging reaches disk from every thread (C-4).** The rolling
  file logger was installed as a thread-local default, so Tokio
  worker events were silently dropped; it is now the global
  default, and lines are assembled whole before redaction and
  rotation instead of treating each `write()` as a line.
- **Windows CI now runs the test suite (C-5).** The Windows
  workflow previously stopped at clippy + build; it runs
  `cargo test` as well. A stale "never compiled" comment in the
  kill-switch module (CI compiles it every run) was corrected.
- **Proxy restore reports and propagates partial failures (H-1,
  L-12, L-13).** The Windows registry restore returns an error
  when any recorded value cannot be restored, deletes values the
  backup recorded as absent instead of leaving VPN-era values
  behind, and decodes UTF-16 registry strings without an
  unaligned `u16` cast.
- **Elevation is checked by token, not group membership (H-2).**
  `IsUserAnAdmin` also returns true for a standard user in the
  Administrators group running un-elevated; the check now reads
  `TokenElevation` from the process token and fails closed.
- **Reconnect rotates across servers (H-4).** The actor retries
  used to hit the same candidate five times. Connect now carries
  a ranked failover list (the UI gathers candidates across all
  countries, not a hardcoded "DE" recommendation), and each
  attempt walks the list round-robin until one connects.
- **The netstack validates what it forwards (H-5).** IPv4 header
  checksums are verified, fragmented datagrams are dropped
  (fragments were parsed but never reassembled or consumed), and
  TCP/UDP checksums are verified before a packet reaches a flow.
- **TCP window scaling is negotiated (H-6).** SYN-ACK now offers
  window scale 2 (a 256 KiB receive window, up from a fixed
  64 KiB), and the peer's scale is parsed and applied; the SYN
  window itself stays unscaled per RFC 7323.
- **DNS cache honours upstream TTLs (H-7).** Cache lifetime is
  the response's minimum answer TTL (never below 5 s, and capped
  by the cache's 60 s freshness policy) instead of a fixed 60 s
  regardless of what the records said; concurrent upstream resolutions are
  bounded (16) instead of one unbounded spawn per query; locally
  generated DNS responses use a rotating IP identification
  instead of a constant. The tunnel-DNS endpoint itself is
  unchanged (see docs/SECURITY.md §2.8).
- **Dead upstream connect path removed (H-8).** An unused
  `H2UpstreamSession::connect` did blocking DNS resolution on a
  Tokio worker; the live path already resolves via
  `spawn_blocking` with a timeout. Lock-poisoning panics
  (H-9) were swept to the recover-from-poison pattern the
  codebase already used in places, and Linux TUN setup (H-10)
  uses idempotent `ip addr replace` instead of matching an
  English "File exists" error string.
- **Control-API hardening (M-2, M-3).** The CSP `connect-src`
  wildcard ports are gone (`'self'` only), an `Origin: null`
  header is no longer accepted (the UI is served by this same
  server, so only its own loopback origins are valid), and
  responses gained Referrer-Policy, COOP and Permissions-Policy
  headers. If the preferred UI port (44123) is taken, the random
  fallback now logs a warning naming the preferred port instead
  of silently binding elsewhere.
- **Credential hygiene (M-5, M-6, M-14).** FxA intermediates are
  zeroized (quick-stretched key, HKDF outputs, HAWK key copies);
  the `authPW` copy inside the login JSON body is overwritten
  immediately after the request is sent. Pending two-factor
  state now expires after 10 minutes, allows at most 5 attempts,
  and is zeroized on expiry, exhaustion and success (it
  previously lived, unbounded, until sign-in or process exit).
  The UI no longer logs the 2FA code it verifies, and the
  password field is cleared on successful login instead of only
  on sign-out. (`StoredSecrets` keeps its `Clone` derive — the
  storage layer needs it — and still zeroizes on drop.)
- **Guardian challenge is solved against the challenged origin
  (M-7).** The proof-of-work cookie was installed under the FxA
  host while the 406 challenge comes from the Guardian host, so
  the retry could never carry it. All three call sites now use
  the challenged request's own origin. The PoW search parameters
  are unchanged (they are server-issued; what difficulty Mozilla
  actually demands cannot be verified offline).
- **Guardian endpoint override is debug-only (M-8).**
  `IFOXY_GUARDIAN_ENDPOINT` used to redirect the bearer token to
  an arbitrary host in release builds; it is honored only under
  `debug_assertions` (tests use it there).
- **Linux DNS guard restores safely (M-10, M-11).** The TUN
  device's `Drop` restores `/etc/resolv.conf` only when the
  file still contains exactly what that device wrote (a newer
  session's DNS is never clobbered by a stale device), the
  journal entry is cleared only on an actual restore, and the
  fallback writer refuses to follow a symlinked
  `/etc/resolv.conf`.
- **Watchdog stop is responsive (M-12)** — the renewal sleep is
  chunked so `stop()` takes effect within ~2 s instead of up to
  the 30-minute renewal interval.
- **Disconnect reports failure (M-13).** A failed disconnect
  command now returns an error to the UI instead of logging
  "disconnected cleanly" unconditionally.
- **Smaller items.** `APP_VERSION` is derived from Cargo.toml
  (M-1; it had drifted). The misleading always-true
  single-instance test helper is removed (M-4). A bogus ACK can
  no longer collapse the per-flow in-flight calculation (L-3).
  IP packet serialization honours the parsed IHL and uses a
  rotating identification instead of the constant `0x4242`
  (L-5). Route prefix masks are clamped to /32 (L-11). A
  duplicate-instance exit shows the fatal-error dialog instead
  of an invisible console message under the Windows GUI
  subsystem (L-15). Authenticode verification now checks
  revocation for the whole chain, warning only when revocation
  servers are unreachable (L-18). The splash subtitle no longer
  says "Windows Desktop Edition" on Linux (L-22).
- **CI and installers.** Workflow permissions are least
  privilege: build jobs run with `contents: read` (including on
  pull requests) and publishing moved to a separate tag-gated
  job with `contents: write` (S-2). Every third-party action is
  pinned to a full commit SHA (S-4). Both installers verify the
  SHA-256 sidecar shipped with each release before installing,
  and refuse on mismatch (S-7).
- **Tests.** New `tests/review3_fixes_test.rs` (7 tests) pins
  the C-1/C-2 recovery behaviour, the M-1 version derivation and
  the H-7 TTL parsing.

Known remaining (deliberately not fixed this wave):
- Local-proxy authentication (H-3): on desktop the proxy binds
  loopback only — the bind address is hardcoded, not
  configurable, so the non-loopback exposure the finding assumes
  cannot occur; and SOCKS5 credentials cannot be presented by
  the OS system-proxy integration the feature exists for. The
  trade-off is documented in docs/SECURITY.md §2.8. Android's
  opt-in non-loopback bind keeps its confirmation dialog and
  startup warning.
- Packet-pump shutdown redesign (M-9): the blocked-reader
  teardown needs a pump architecture change. The concrete harm
  it enabled (a stale device clobbering a newer session's
  resolv.conf) is closed by the M-10 content guard above.
- Android: the upstream-trust store merging system roots (A-2)
  is by design; alpha-channel dependencies (A-4) have no stable
  equivalents yet and ProGuard keep narrowing still needs
  on-device validation of a minified build.
- All three platform workflows publish into the one combined
  release (S-3) — that is the product's release shape, kept.
  Dependency audit automation (S-5) is not added; Cargo.lock is
  committed and CI builds resolve against it.
- Carried over unchanged: UI/service privilege split (redesign),
  TOTP-only FxA sign-in, gateway-less (PPP) route detection on
  Linux, Android lint report-only and dependency locking
  (reasons in the 0.2.2 entry).

## 0.2.2 — Second external-review wave

Fixes from a second full external code review of the v1.0.20 tree.
Every finding was re-verified against the source before being acted
on; the review was accurate on all code claims, with two framing
corrections (the open-proxy risk was understated as silent — it is
opt-in behind an explicit confirmation dialog; the Windows kill-switch
statements describe different test levels, not a contradiction).

- **Recovery replay failure is now fatal at startup.** A recovery
  journal that exists but cannot be read/parsed used to be logged
  and ignored while startup continued into a connectable UI, risking
  a half-restored network state. Startup now refuses with a fatal
  error naming the journal file and the manual recovery step
  (delete the journal, check the previous session's routes/proxy by
  hand). Regression tests pin both directions: corrupt journal is
  an error, missing journal is a clean start.
- **Token renewal uses the live credential provider.** The renewal
  worker used to re-send the connect-time access token forever, so a
  long session died at renewal once that token expired (and the
  `TokenRefreshed` command only updated the H2 session, never the
  worker). The actor now carries the `FxaTokenProvider` from the
  Connect command through initial connects AND reconnect attempts,
  so each renewal cycle fetches a fresh (possibly refreshed) token;
  provider failures still warn and retry later. Callers without a
  provider keep the old static-token behaviour.
- **Docs reconciled.** `docs/SECURITY.md` §2.2 claimed a medium-
  integrity UI — stale: the whole process runs elevated, and the
  section now says so. `docs/TESTING.md` quoted 99 tests / 27
  targets and `docs/FIX_TRACKER.md` 107 / 27; both were stale and
  neither was dated or commit-pinned. Current: 121 test functions
  across 31 files; Linux run on this tree: 112 passed, 0 failed,
  1 ignored (root-only TUN test). README kill-switch lines now
  distinguish filter-API read-back tests (exist, admin-required,
  opt-in) from end-to-end leak verification (still not done on real
  Windows).

Known remaining (deliberately not fixed this wave, same reasons as
before unless noted):
- UI/service privilege split: a redesign (unelevated UI + hardened
  privileged service with ACL'd IPC), not a patch. The current
  elevated-everything model, the install-location confirmation and
  the `IFOXY_ALLOW_PORTABLE=1` bypass are documented as-is.
- TOTP-only FxA accounts cannot sign in; gateway-less (PPP) default
  routes are undetected on Linux; local-proxy authentication is
  still absent (non-loopback bind stays opt-in behind an explicit
  risk confirmation, default loopback).
- Android dependency locking/verification and a CI dependency scan:
  need a Gradle run to generate the lock/verification files, which
  this sandbox cannot do (Gradle daemon does not run here); direct
  dependencies are all exact pins, so the exposure is transitive
  drift only.
- Android lint stays report-only (`abortOnError = false`, no lint
  step in the release workflow): there is no lint baseline file, so
  flipping the gate blind risks a red CI; the baseline must be
  cleaned first.
- ProGuard keep narrowing and minified-release on-device validation
  remain pending on-device work; no record of a minified release
  APK run exists yet.

## 0.2.1 — External-review fix wave

Post-release corrections (shipped in the combined v1.0.20 release;
the v1.0.16/v1.0.17/v1.0.18/v1.0.19 tags were withdrawn): the Linux secret-key
reader retries briefly on a wrong-length key file before declaring
corruption — a concurrent creator's `create_new` makes the file
exist empty for a moment, and readers in that window intermittently
failed saves (and two token-provider tests in CI); `paths::home_dir`
is now compiled only on non-Windows targets, where it is used
(Windows clippy `-D warnings` flagged it as dead code).

Fixes from a full external code review of the 0.2.0 / Android 1.0.15
tree. Every finding was re-verified against the source before being
acted on; the review's verdicts and the two places where it was wrong
(WFP block weight lives at 0 in the production backend — the stale 5
was in SECURITY.md and the test mock; the cancellation test's edge
target was always a local blackhole) are recorded in the project notes.

High severity:
- **ProxyOnly bind failures are fatal.** `LocalProxyServer::start`
  binds before spawning and returns the error; the state machine no
  longer enables the system proxy against a dead port while reporting
  Connected (H1).
- **Linux kill switch hardening.** An ip6tables failure now rolls back
  the IPv4 chain instead of leaving a DROP-terminated chain with no
  owner; iptables calls wait on the xtables lock (`-w`); removal
  reports incomplete teardown; the guard is journaled through the
  shared recovery journal, so a crash no longer leaves the chains
  behind with no recovery record (H2).
- **Kill switch survives reconnect exhaustion.** After 5 failed
  Full-mode reconnects the carried kill switch is retained by the
  actor (traffic stays blocked, state Failed explains why) instead of
  being dropped fail-open; it is released on explicit disconnect or
  disarmed — never cleaned — when a new session's kill switch
  supersedes it (H3).
- **Control API Content-Length fixed.** The 401 and two 400 responses
  carried hand-written lengths (42/17) shorter than their bodies
  (46/19); all plain responses now derive the length from the body
  (H4).
- **Linux elevation preserves the user's session.** The pkexec
  relaunch passes HOME, the XDG dirs, and the display/bus variables
  through, so the session file and recovery journal live in the
  invoking user's config dir, not root's (H5).
- **Packet parser + pump supervision.** `Ipv4Header::parse` rejects
  total_length smaller than the header (was an underflow panic on
  crafted packets); a packet-pump task that dies while running now
  reports a dropped connection to the state machine instead of
  blackholing traffic behind a Connected state (H6).

Medium:
- ProxyOnly reconnects inherit the previous system-proxy guard: no
  direct-traffic window and no backup corruption (M4). HTTP CONNECT
  forwards bytes pipelined after the headers instead of dropping them
  (S2). The relay idle timer counts completed writes as activity (M3).
- Recovery journal is one shared instance with fsync'd write-ahead
  flushes and section-scoped cleanup; a failed proxy restore keeps
  its journal record for next-startup replay (S6). The resolv.conf
  fallback is journaled the same way (M1).
- Linux secret store: the key file is created atomically at mode 0600
  (create_new), a corrupt key is an error instead of silent
  regeneration, session writes are atomic, and clear() removes the
  key for the default store (S3).
- Auth: refresh rejections only clear credentials when the grant is
  really dead (401 or 400 invalid_grant) — a CDN 403 no longer logs
  the user out; get_auth_state follows the token provider; logout
  reports honestly whether server revocation landed; FxA errno 120
  (email case) retries with the canonical address; the password and
  derived authPW are zeroized after use; in-app logs are capped at
  500 lines and email addresses are masked in them (S7–S9).
- Install-location check canonicalizes paths before comparing (S5);
  the Linux single-instance lock falls back to the user's state dir
  instead of /tmp (S5); the Guardian endpoint honors
  IFOXY_GUARDIAN_ENDPOINT, which also makes the actor cancellation
  test fully hermetic (M5).
- Docs/process: README version pins removed, ProxyOnly IP-leak
  warning added (EN+FA), DPAPI entropy wording corrected, SECURITY.md
  WFP weight (0) and WebView2 static-loader provenance corrected,
  LICENSE added at the root, crate package renamed ifoxy-windows →
  ifoxy (D1–D7).

Known remaining items (confirmed by the review, deliberately not in
this wave): TOTP-only FxA accounts cannot sign in (email 2FA only);
the reconnect path reuses the connect-time access token instead of
the provider's refreshed one; gateway-less (PPP-style) default routes
are not detected on Linux; Android ProGuard keep rules for Netty are
unchanged pending on-device validation.

Test note: `test_netstack_5000_short_server_closed_flows_zero_residual`
is load-sensitive and intermittently times out under CPU contention on
the pre-existing tree as well (verified by A/B runs with the wave
stashed: 2/4 failures without it, 1/4 with it); it passes consistently
on a quiet machine. Not a regression of this wave.

## 0.2.0 — Linux port with full TUN mode

- The desktop client now builds and runs on Linux alongside Windows,
  with the complete Full (TUN) mode — not just the proxy:
  - `/dev/net/tun` device (IFF_TUN | IFF_NO_PI) configured through
    iproute2, sharing the same user-space netstack and packet pump as
    the Windows Wintun path.
  - Routing through a Linux `NetworkBackend`: the default gateway is
    read from `/proc/net/route`, routes are installed with `ip route`
    (gateway form first, device form as fallback), all behind the same
    write-ahead recovery journal and atomic rollback as Windows.
  - Tunnel DNS (1.1.1.1) via systemd-resolved per-link settings
    (`resolvectl`) when available, otherwise a backed-up
    `/etc/resolv.conf` rewrite that is restored on disconnect.
  - Kill switch through dedicated iptables/ip6tables chains mirroring
    the WFP policy: loopback, DHCP, the edge, and tunnel traffic are
    permitted; everything else is dropped (IPv6 blocked outright while
    connected). A failed install stays fatal — Full mode never reports
    "connected" without the kill switch.
  - Elevation through pkexec (PolicyKit); single instance via an
    flock-held lockfile; XDG config/data/state directories.
  - Secret storage uses ChaCha20-Poly1305 with a random per-user key
    (0600 key and session files) — the Linux counterpart of DPAPI's
    user scope.
  - ProxyOnly mode sets the GNOME system proxy through `gsettings`,
    executed as the desktop user (an elevated process must not write
    root's dconf database).
- Known Linux differences in this release:
  - The install-location prompt (Windows message box) is log-and-warn
    only on Linux; installing under `/opt` is recommended (see
    `install-linux.sh`).
  - Route-change detection polls every 5 s (no NotifyRouteChange2
    equivalent is wired yet); the Windows event-driven path is
    unchanged.
- Windows behavior is unchanged; all platform code is behind the new
  backend/trait seams (`NetworkBackend`, `FirewallBackend`,
  `TunDeviceOps`, per-OS system-proxy store).
- Fixes from the port work (both platforms):
  - The local proxy's SOCKS5 handshake timeout no longer wraps the
    upstream CONNECT — a slow edge was previously reported as a failed
    handshake (and failed the relay test deterministically under
    tokio's paused test clock).
  - `LocalProxyServer::stop()` now owns and joins the accept task, so
    the listening port is guaranteed released when stop returns; loopback
    listeners are bound with SO_REUSEADDR so a fast disconnect/reconnect
    cannot lose to a TIME_WAIT socket on Linux.
  - ProxyOnly mode on Linux requires a GNOME-compatible settings
    backend (`gsettings` with the desktop schemas); on other desktops
    the connect fails loudly at the system-proxy step instead of
    pretending the system proxy was set.

## 0.1.0

- Initial Windows release (Wintun full-tunnel mode + WFP kill switch).
