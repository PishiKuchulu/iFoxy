# Changelog

## 1.0.21 (versionCode 58) — second external-review wave

- **Netty 4.1.119.Final → 4.1.139.Final** (all four artifacts:
  handler, codec-http2, transport, handler-proxy). The October 2026
  release is a security release fixing codec-http2, codec-http and
  handler issues present in 4.1.119. Note: Netty 4.1 reaches
  End-of-Life 2027-07-01; migrating to 4.2 is tracked future work.
- **Encrypted-store fallback is fail-closed.** The old
  `createEncryptedPrefsWithRecovery` fell back to a PLAINTEXT
  SharedPreferences file on the second failure — OAuth tokens, the
  multi-account vault and cached credentials could be written to
  disk unencrypted, and no code ever read that file back or deleted
  it. The fallback is removed entirely: persistent failure now
  yields a session-only in-memory store (nothing touches disk; the
  session must be re-entered after restart), and any leftover
  `_plain_fallback` file from the old version is deleted
  best-effort whenever the store opens (it was never read by any
  version, so deletion loses nothing). New unit tests cover the
  in-memory store's semantics (7 tests).
- **Control-plane `protect()` failure is fail-closed.** A refused
  `VpnService.protect()` used to log a warning and hand the
  unprotected socket back, routing control-plane traffic through
  the tunnel. The socket is now closed and the request fails with
  a connect error. The null-protector case stays as the explicit
  no-protect path (proxyOnlyMode sets it deliberately — no TUN
  exists to leak into).
- **Known remaining, unchanged:** TOTP-only FxA sign-in; ProGuard
  keep narrowing and minified-release on-device validation (no
  record of a minified release run exists yet); dependency locking
  (needs a Gradle run to generate lock files); lint report-only
  (no baseline; flipping the gate blind risks red CI). Non-loopback
  proxy bind stays loopback-default and opt-in behind the explicit
  risk confirmation dialog plus the SEC-FX-05 startup warning.

## 1.0.20 (versionCode 57) — fix-wave correction, round 4

- No Android code changes. The v1.0.19 tag's Linux build failed in
  tests: the 50-cycle proxy lifecycle test's initial bind can lose a
  sub-50ms race against an unrelated tenant of a shared CI machine
  briefly holding the test port (the conflicting LISTEN socket was
  not owned by this process). The test now serializes on the proxy
  port lock and retries the initial bind the same way the existing
  rebind check does. The v1.0.19 release was withdrawn and is
  superseded by this one.

## 1.0.19 (versionCode 56) — fix-wave correction, round 3

- No Android code changes. The v1.0.18 tag's Windows build failed
  clippy on `clippy::empty-line-after-outer-attr` in
  tests/wfp_killswitch_test.rs: a blank line after the
  `#[ignore = ...]` attribute of three Windows-only tests. The lint
  is invisible on Linux CI because the whole test is cfg'd out
  there. The blank lines are removed. The v1.0.18 release was
  withdrawn and is superseded by this one.

## 1.0.18 (versionCode 55) — fix-wave correction, round 2

- No Android code changes. This bump keeps the combined release
  aligned with the desktop-side corrections that the v1.0.17 tag's
  Windows/Linux builds failed on: the Linux secret-key reader now
  tolerates a concurrent creator's write window instead of reporting
  a corrupt key (it intermittently failed two token-provider tests in
  CI), and `paths::home_dir` is compiled only on non-Windows targets
  (Windows clippy flagged it as dead code). The v1.0.17 release was
  withdrawn and is superseded by this one.

## 1.0.17 (versionCode 54) — fix-wave correction

- **Material3 stays on 1.4.0-alpha10.** The 1.0.16 tag pinned
  Material3 to stable 1.3.1, which does not ship the expressive API:
  the app theme uses `MaterialExpressiveTheme` and `MotionScheme`,
  which are internal/unresolved in 1.3.1, so the Android build of the
  v1.0.16 tag failed to compile (`:app:compileDebugKotlin`). The pin
  reverts to the alpha line the theme was built against; moving to a
  stable Material3 has to wait until a stable release ships the
  expressive API. The broken v1.0.16 release was withdrawn; 1.0.17
  supersedes it with no other changes.

## 1.0.16 (versionCode 53) — external-review fix wave

Fixes from a full external code review of the 1.0.15 tree (each finding
re-verified against the source first):

- **Netty 4.1.115 → 4.1.119** (current 4.1.x security line);
  security-crypto 1.1.0-alpha06 → alpha07 (A1, A2). Material3 was
  briefly pinned to stable 1.3.1 in this wave and reverted in 1.0.17 —
  see the entry above.
- **Debug logs no longer reach logcat in release builds**: AppLogger.d
  is gated on BuildConfig.DEBUG and ProGuard strips Log.v/Log.d calls;
  the debug lines carry connection targets (A4).
- **Upstream TLS trust no longer includes user-installed CAs**: the
  merged trust store takes the platform anchors from the default trust
  manager (which follows the app policy) instead of enumerating the
  raw AndroidCAStore, plus the bundled GlobalSign roots (A5).
- **In-app updater verifies downloads**: the asset's SHA-256 from the
  GitHub API is checked before install, and only the canonical
  `iFoxy-v<version>.apk` asset name is accepted — the any-`.apk`
  fallback is gone (A6).
- **hev tunnel session cap**: `max-session-count` 0 (unlimited) → 512,
  in line with the local proxy caps (A7).
- **Release workflow fails fast** with a clear error when the signing
  secret is missing, instead of failing obscurely at the APK rename
  step on an unsigned build (A8).
- **Widget** has a distinct connected background (it previously shared
  the disconnected one) (A9); `supportsRtl` is now true (A10 — full
  Persian string resources remain a separate follow-up).
- Ships together with the desktop 0.2.1 fix wave in one combined
  release.

## 1.0.15 (versionCode 52) — Linux desktop release companion

- No Android changes in this release. The version bump accompanies the
  desktop client's Linux port (with full TUN mode), which ships in the
  same combined GitHub release.

## 1.0.14 (versionCode 51) — splash crash fix

- **Fixed a launch crash in 1.0.13**: the splash loaded the app icon via
  `painterResource(R.mipmap.ic_launcher)`, which on API 26+ resolves to
  the adaptive-icon XML — Compose only accepts vector drawables and
  raster images there, so the app crashed on open
  ("Only VectorDrawables and rasterized asset types are supported").
  The splash now uses a raster copy of the flattened launcher icon
  bundled as `drawable-nodpi/app_icon.png`.

## 1.0.13 (versionCode 50) — new splash

- Splash screen redesigned per Farzad's spec: the orange power medallion
  is replaced by the app icon itself, the "iFoxy" wordmark and the
  spinner are gone.
- The loading indicator is now a native Compose port of his ripple-dots
  SVG: a dot grid inside a disc, lit by two expanding rings on a 2.8 s
  cycle (second ring half a cycle behind), drawn on a Canvas with the
  dark-surface ink (#F5F5F7) matching the splash background. The
  light-surface variant (#131316 ink) is a one-line parameter change in
  `RippleDotsLoader` if a light splash is ever wanted.

## 1.0.12 (versionCode 49) — multiple accounts with automatic quota rotation

- **Multiple Firefox accounts**: sign in with several accounts
  (Settings → Account → Add account) and keep them all on the device.
  Accounts live in an encrypted vault; the current session is untouched
  plumbing — activation swaps which account's tokens are live. The
  existing single-account session migrates into the vault automatically
  (its email is read from the FxA profile endpoint).
- **Automatic switch on quota exhaustion**: every Guardian proxy-pass
  mint (initial connect, in-place renewal, watchdog redial) goes through
  one rotation-aware path. When the active account's quota is exhausted
  (Guardian HTTP 429, or a minted pass reporting zero bytes remaining),
  the account is marked exhausted, the next account with quota left is
  activated, and the connection continues on it — bounded by the number
  of stored accounts. A notification announces the switch.
- **Account management**: Settings → Account lists every account with its
  live quota snapshot and Active marker; "Use" switches manually (the
  tunnel re-dials immediately), the trash icon removes an account
  (removing the active one falls through to the next account, or signs
  out when none remain — the Sign out button follows the same rule).
- Quota snapshots are kept per account (proxy-pass headers and Guardian
  status both feed them); refreshed tokens are harvested back into the
  vault on every switch. Rotation selection is unit-tested.

## 1.0.11 (versionCode 48) — in-app updates

- **In-app updater** (same pattern as Anvex/PishiMovie): the app checks
  this repository's GitHub releases on launch and offers newer versions
  in a dialog — download with live progress and cancel, then install via
  FileProvider (with the Android "install unknown apps" consent flow).
- Settings → About gains an **App update** row with the live status and
  a manual Check / Download / Install action.
- Release selection is monorepo-aware: only strict `vX.Y.Z` releases
  that carry an Android APK asset count (Windows-only tags and the
  combined releases' `.exe` assets are ignored). Version comparison and
  selection are unit-tested.
- Note: 1.0.10 and earlier have no updater — install 1.0.11 manually
  once; updates after that arrive in-app.

## 1.0.10 (versionCode 47) — Home card & logo fixes

- **Header logo:** the README banner is shown as-is (transparent PNG,
  no plate behind it).
- **Location card rebuilt horizontally** (flag · name + status ·
  chevron): the status line ("Last used") could be clipped by the old
  vertical layout's fixed height; that can no longer happen.
- **Recommended location shows the real country:** the "Recommended"
  entry is a pseudo-location (code REC) in the server data. When it is
  selected, Home now displays the actual exit country and flag resolved
  from the exit IP once connected (and "Recommended" before that),
  instead of the pseudo-location's raw label.

## 1.0.9 (versionCode 46) — UI fixes from on-device testing

- **Theme fixed:** the Home palette now follows the day/night toggle
  (light = brand yellow, dark = ink) instead of switching with the
  connection state; connecting no longer recolors the app, and the header
  theme button visibly works on every screen.
- **Home simplified:** the flag card is the only location entry point
  (tap it to choose a location); the Recommended card and the Select
  Location pill were removed.
- **Header:** the README banner (`logo-horizontal.png`) replaces the
  text wordmark.
- **Home no longer scrolls:** the layout is fixed-height and the
  "Protected by your Firefox account" footer is always visible.
- **Settings rebuilt:** each category is now a card that expands like a
  menu when tapped, on a background that matches the Home screen.
- **Release asset renamed:** the APK ships as `iFoxy-v<version>.apk`
  instead of Gradle's default `app-release.apk`.

## 1.0.8 (versionCode 45) — hardening & stability

> Rebrand: the app is now **iFoxy** (package `com.pishi.ifoxy`), the Android
> half of the iFoxy monorepo alongside iFoxy for Windows. It is based on
> FoxyVPN 1.0.7 by Vauth (MIT). Settings were regrouped into consistent
> categories (Connection · DNS · Local proxy · Split tunneling · Advanced ·
> About · Account) and the launcher icon now uses the iFoxy fox logo.
>
> UI/UX: the Penpot "iFoxy — Screens" design is implemented — brand-yellow
> connected home and ink-dark disconnected home with the drifting world
> map (90 s / 120 s seamless loop) and the pulsing neon power halo
> (alpha 0.35↔0.60, scale 1↔1.06, 2.4 s), dark Choose-location and
> Sign-in screens, Poppins throughout. All elements are wired to real
> state (last-used + recommended servers, session bytes, ping, exit IP,
> Guardian quota); sign-in behaviour and secret handling are unchanged.

Security fixes:
- The Firefox password and 2FA code are no longer kept in `rememberSaveable`
  state (they could be persisted to disk by the system); they live in memory
  only. The email field is unchanged.
- The quick-connect widget's toggle broadcast is now guarded by a per-install
  random token: other apps can no longer start/stop the VPN by broadcasting
  the widget's action.
- Cookie handling hardened: `Secure` and `Path` attributes are honoured, and
  Fastly challenge cookies are kept under the domain that issued them instead
  of being widened to all of `firefox.com`.
- Fail-closed TUN setup: if the IPv6 default route cannot be claimed, the
  connection is refused instead of leaking IPv6 traffic outside the tunnel.
  (App bypass of the tunnel remains impossible by default: the VPN Builder
  only allows it after an explicit `allowBypass()` call, which is never made.)
- Binding the local proxies to a non-loopback address (open proxy, no
  authentication) now requires an explicit risk confirmation in Settings and
  logs a prominent warning at startup.
- Log redaction now also covers authorization/cookie headers and JSON token
  fields, not only `Bearer` tokens. The cached real (pre-VPN) IP/country moved
  from plaintext preferences into the encrypted store.

Stability fixes:
- A partial wake lock is now actually held while connected (previously only
  the Wi-Fi lock was taken), so Doze can no longer stall the tunnel.
- A corrupted encrypted-preferences store no longer crash-loops the app at
  startup; the store is reset and recovered (one re-login).
- Resource use is bounded: relay thread pool capped, per-server connection
  limit 256, and a per-stream receive-buffer cap that fails a single stream
  instead of OOM-killing the tunnel.

Build & project:
- Gradle wrapper (8.10.2) is committed; use `./gradlew` (see README).
- The hev-socks5-tunnel native dependency is pinned to an exact commit and
  verified during the build.
- CI builds and unit-tests every push to `main`; lint is checked on release
  builds again and its report is uploaded.
- First unit tests added: FxA PBKDF2/HKDF known-answer vectors, fake-DNS
  range, hostname/DoH validators, TLS ClientHello splitter, log redaction.

Known limitations (unchanged in this release):
- No UDP data plane (QUIC/games/WebRTC fall back to TCP or fail); only DNS
  is relayed, over DoH.
- No app-level kill switch beyond the fail-closed TUN setup above; use
  Android's "Always-on VPN" + "Block connections without VPN" for a strict
  system-level kill switch.
