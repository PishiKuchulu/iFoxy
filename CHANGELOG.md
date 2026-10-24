# Changelog — iFoxy desktop (Windows & Linux)

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
