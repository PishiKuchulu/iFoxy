# Changelog

## 1.0.34 (versionCode 71) - upstream Fastly solver port

- The native Fastly challenge solver now follows upstream
  FoxyVPN v2.0.2's design. A 406 whose body is a challenge page
  is solved directly; an empty-body 406 (the on-device case) is
  answered by probing the challenged host, then
  api.accounts.firefox.com, then accounts.firefox.com, under
  the app's native, browser and desktop user agents. The
  challenge list is parsed with a JSON tokenizer with prefix
  validation (the old single-regex parser broke on real scripts
  whose challenge data contains nested arrays), post-back runs
  up to 8 rounds, an interactive CAPTCHA is a hard failure, and
  the clearance cookies are installed per FxA host in the
  shared control-plane jar and mirrored into the WebView
  cookie store.
- Browser sign-in clearance: a "no answer" in-page exchange
  outcome (status 0 or -1 — on-device, 2026-11-09, the cookie
  retry died with "TypeError: Failed to fetch") no longer
  aborts the recovery before the WebView-navigation step; only
  a real FxA answer ends the flow. Regression tests cover the
  gate classification.
- Token renewal: the refresh grant is attempted against
  oauth.accounts.firefox.com first and retried against
  api.accounts.firefox.com only when bot protection blocked
  the first attempt — the two hosts sit behind independent
  Fastly fronting, and each attempt runs the solver first. A
  block on both hosts still classifies as blocked, so the
  v1.0.31 fail-fast behaviour is unchanged.

## 1.0.33 (versionCode 70) - external-audit fix wave

- The public connection state now matches the notification while
  the watchdog recovers: it reports Reconnecting while redialing
  or waiting for a network instead of staying Connected, and
  returns to Connected when the connection is healthy again.
  Home, the quick-settings tile and the widget render the new
  state.
- A transient 400/403 from the token endpoint no longer erases
  the stored session and signs you out: a refresh rejection is
  permanent only on HTTP 401 or FxA errno 110 (invalid token).
  Regression tests cover the new classification.
- The in-memory fallback store behind the encrypted preferences
  is now one shared instance per store, so a sign-in saved by one
  component in a fallback launch is visible to the others.

## 1.0.32 (versionCode 69) - browser clears the challenge for sign-in

- Fixed sign-in failing on flagged networks even through the
  browser flow (on-device, 2026-11-06): the sign-in pages loaded
  and the session was captured, but the in-page token exchange
  itself returned HTTP 406 — the exchange fetch sends no cookies
  and cannot execute Fastly's JavaScript challenge, so the trust
  the page earned did not carry to the API host, and the native
  fallback hit the same dead end as before.
- The in-page exchange now recovers from a block: it retries with
  the browser's cookies, then opens the API host itself in the
  WebView so the real browser solves the JavaScript challenge
  and stores the clearance cookie, and polls the exchange from
  that context until it answers (bounded at ~75 seconds).
  Regression tests cover the block classification and the
  API-origin derivation the recovery keys off.

## 1.0.31 (versionCode 68) - blocked session renewal fails fast

- Fixed the doomed-retry connect failure seen on-device on
  2026-11-06: when the access token had expired, the renewal
  request was blocked by Mozilla's bot protection (HTTP 406, the
  native challenge solver cannot clear it on a flagged network),
  yet the connect flow carried on with the dead token — Guardian
  rejected it (401), entitlement activation with the same token
  rejected it again, and the cycle repeated for four attempts
  across every candidate server before failing with a misleading
  "could not reach a VPN server" message.
- Renewal failures are now classified: a bot-protection block or
  a permanent FxA rejection is fatal for the connect attempt,
  which stops immediately with a message that names the way out
  (switch networks, or sign out and sign in again — the browser
  sign-in route is not subject to the native 406 block). Only
  genuinely transient renewal failures keep the old fallback.
  Regression tests cover the classification.

## 1.0.30 (versionCode 67) - disconnect crash fix

- Fixed a crash when disconnecting: the Home session timer
  dereferenced the connection start time with `!!` inside its
  one-second loop while disconnect nulls that value, so a tick
  resuming in the cancellation window killed the app with an NPE
  (reported on-device on 1.0.29). The timer now captures the start
  time before the loop and never dereferences the live value.
- Crash reports now record the app version and Android/device
  context at the top of the crash file.
- The release workflow now keeps the R8 mapping as a build
  artifact, so crash traces from a shipped build can be
  deobfuscated instead of being lost with the CI runner.

## 1.0.29 (versionCode 66) - updater honesty fix

- The in-app updater no longer claims "You're up to date" when the
  update check itself fails at the HTTP level — most visibly
  GitHub's unauthenticated rate limit (HTTP 403), which shared VPN
  egress IPs hit routinely; that is how the live v1.0.28 release
  stayed hidden from phones on 1.0.27. A non-successful response is
  now a failed check, and the dialog shows the status code
  ("Couldn't check for updates (HTTP 403)") instead of a false
  up-to-date. Regression tests cover the status gate.

## 1.0.28 (versionCode 65) - UI/UX audit fix wave

Fixes from a dedicated UI/UX audit of 1.0.27 (52 findings across
both clients). Android highlights:

- Browser sign-in: page load failures (offline, HTTP errors) now
  show an in-app error with Retry and Open logs instead of a blank
  page; rotating the phone no longer restarts the sign-in flow
  (the activity now handles config changes itself).
- Server list: cities show their names (not codes); a search field
  filters countries/cities; single-line texts ellipsize instead
  of clipping mid-word.
- Light theme: the Connected status reads the theme's status
  colors (readable green on white), muted text on the brand yellow
  is darker, and the always-dark screens (sign-in, servers) keep
  light status-bar icons.
- Settings: switch rows are single accessible switches; section
  headers announce expanded/collapsed; the update dialog's SHA-256
  prints in 16-character blocks; dialogs cap their height and
  scroll; buttons meet the 48 dp minimum; errors announce to
  TalkBack (live regions).
- Home/servers/settings/logs content is capped at 520 dp wide on
  tablets and foldables; logs render in monospace; the widget and
  Quick Settings tile use a power icon (state-tinted) instead of
  the stock Android padlock, and the widget status text is 12sp
  single-line.

Deferred with reasons (unchanged by this wave): unifying the
typography scale (21 font sizes / 51 ad-hoc styles) and a spacing
token system — appearance-wide refactors that need a screenshot
QA pass; three named off-grid spacing values were rounded here.


## 1.0.27 (versionCode 64) - granular-audit fix wave

Fixes from a full component-by-component audit of the app (UI/UX,
logic, performance, security). Highlights:

- Server list: tapping a city with no available servers now shows the
  message (it was set but never displayed); stale-cache caption +
  Retry added; country-header chevron removed; city rows are 48 dp
  radio-selectable rows.
- Theme: wallpaper dynamic color is off by default, so the brand
  palette is what ships; a Theme picker (System/Light/Dark) now
  exists in Settings; footer text contrast raised.
- Browser sign-in hardening: the spoofable default-origin bridge
  overload is gone; a missing `verified` flag now counts as
  unverified and success-URL matching is stricter; FLAG_SECURE
  protects the sign-in screen; file/content access disabled in the
  WebView; a caption + delayed Cancel appear during the token
  exchange.
- Home: live download/upload rates; quota pill also shows while
  disconnected; real-IP lookup honors the "Verify exit location"
  toggle and can be shown while disconnected; scrollable layout
  (no clipping at large font sizes); connect debounce + connecting
  spinner; picking a location while connected now restarts the
  tunnel to the new location.
- Settings: values refresh on resume; every save confirms with a
  snackbar ("applies on next connection" for connection settings);
  field-level error texts; sign-out asks for confirmation; dialog
  inputs survive rotation; new Account-alerts toggle.
- Logs: account emails are masked centrally in the in-app log;
  Copy confirms with a toast; Clear asks first.
- Updater: a failed update check now reports "Update check failed"
  instead of "You're up to date".
- Widget shows its connection state as text, not color alone.

Deferred with reasons (unchanged by this wave): surfacing proxy
failover health in the UI; a monochrome QS-tile brand icon (no
suitable drawable ships yet).


## 1.0.26 (versionCode 63) - token exchange inside the browser page

- The /oauth/token exchange after a browser sign-in now runs inside the
  signed-in Mozilla page itself (a fetch from the page's own trusted
  network context, Hawk-signed by the app), after both solver variants
  proved unable to clear the Fastly challenge on some networks: the
  challenge served to the native client could not be completed there.
  The native exchange with the challenge solver remains as the fallback
  when the in-page exchange is unavailable or fails.
- Diagnostics: the head of an HTTP 406 challenge body and the in-page
  exchange outcome are now written to the in-app log.


## 1.0.25 (versionCode 62) - settings and logs reachable while signed out

- The sign-in gate no longer locks the user out of the rest of the app:
  the sign-in screen now links to Settings and Logs, and the browser
  sign-in error state offers "Open logs" directly. Previously a user
  whose sign-in failed (for example the HTTP 406 case) could not reach
  diagnostics at all, because every other screen sat behind login.


## 1.0.24 (versionCode 61) - 406 challenge-solver fix

- The Fastly challenge solver now solves the challenge carried by the actual
  HTTP 406 response (the approach upstream FoxyVPN shipped in its v1.0.8):
  in 1.0.23 the browser sign-in succeeded on Mozilla's page, but the
  follow-up token exchange could still be 406-blocked on flagged networks
  because the solver fetched a fresh challenge page from the host root
  instead of solving the one that was served.
- Solver robustness from upstream: tries both the Mozilla VPN and a desktop
  Chrome user agent, threads one user agent through all challenge
  sub-requests, seeds the solver cookie jar from the app jar, and detects
  challenge pages more reliably.
- When the challenge cannot be solved, sign-in and Guardian calls now fail
  with an actionable message (switch networks and try again) instead of a
  bare "HTTP 406".
- Fork security fix retained: challenge cookies stay under their issuing
  domain (SEC-FX-03).


## 1.0.23 (versionCode 60) — browser sign-in (Mozilla anti-bot fix)

Desktop ships unchanged as 0.2.3 in the same combined release;
this wave is Android-only.

- **Sign-in moved to Mozilla's official page, inside the app.** The
  direct API login (email + password against
  `api.accounts.firefox.com`) is now blocked by Mozilla's bot
  protection (HTTP 406) for many users, so fresh sign-ins failed
  while already-signed-in sessions kept working. Sign-in now opens
  the official Firefox Accounts page in an in-app browser view; the
  password and any verification code are entered on Mozilla's page
  and never pass through this app's code, and two-factor / email-code
  verification is handled by the page itself. The page hands the app
  a session token through the FxA WebChannel protocol, which is
  exchanged for the same OAuth access/refresh tokens as before.
  Firefox accounts that sign in with Google or Apple cannot be used
  on the in-app page (Mozilla does not support them in embedded
  browsers). Existing sessions are unaffected — stored refresh
  tokens keep working and only fresh sign-ins use the new flow.
  Removed with the old flow: the in-app credential form, the
  `/account/login` call and its password-stretching code, and the
  pending-session-token store (the PBKDF2 primitive itself is
  retained, pinned by its known-answer tests). The multi-account
  vault now files a browser sign-in by asking the FxA profile
  endpoint for the account's email after the session is established.
- **Guardian 401 spiral fixed.** When Guardian rejected a stored
  access token, the connect path activated the entitlement with the
  same dead token and failed with a second 401 ("failed to activate
  guardian entitlement: HTTP 401"). It now renews the token first
  and only falls back to activation if the renewed token is also
  rejected (or renewal itself fails).
- **Update dialog redesigned.** The plain system dialogs are
  replaced by the themed update popup designed for Anvex — dark
  glassy card, glowing download glyph, current → new version card,
  asset chip with the expected SHA-256, gradient progress bar with
  byte counter, breathing glow/border and a shimmer sweep while
  downloading — restyled to the iFoxy palette and Poppins. The
  update controller, its state machine, and the wave-3 download
  verification (mandatory digest + release-signer check) are
  unchanged.
- **Control-plane User-Agent corrected** to report Android
  (`sys:android 14`); it previously claimed `sys:linux` (finding
  A-5a from the second review, fixed upstream in their v1.0.8 as
  well).

## 1.0.22 (versionCode 59) — third external-review wave

Desktop ships as 0.2.3 in the same combined release; the desktop
half of this wave (recovery-journal hardening, netstack checksum
validation and window scaling, control-API tightening, CI
least-privilege and SHA pinning) is listed in the root CHANGELOG.
Android-specific items:

- **In-app updater verifies what it installs (A-1).** Two of the
  three checks around the self-update were missing. A release
  whose metadata carried no SHA-256 digest was installed with NO
  hash verification at all (the digest is nullable in the update
  metadata and the null case skipped the comparison); the updater
  now fails closed — no digest, no install, partial download
  deleted. And the downloaded APK's signing certificate is now
  compared against the release certificate fingerprint
  (`f5381666…0bee`) before the installer opens; a mismatch deletes
  the file and aborts. `REQUEST_INSTALL_PACKAGES` stays in the
  manifest: the in-app updater cannot request an install without
  it. What was broken was never the permission — it was the
  absent verification around it, which is now in place.
- **Widget toggle (A-3) re-verified, no change:** the exported
  receiver the review flagged already requires the per-install
  `WidgetToggleGuard` token; broadcasts without it are dropped.
- **Known remaining, unchanged:** upstream-trust store merges
  system roots by design (A-2); alpha-channel dependencies
  (security-crypto, material3) have no stable equivalents yet
  and the Netty ProGuard keep rule stays wide until a minified
  release is validated on a device (A-4); TOTP-only FxA sign-in;
  dependency locking (needs a Gradle run to generate lock
  files); lint report-only (no baseline yet). Non-loopback proxy
  bind stays opt-in behind the risk confirmation dialog plus the
  SEC-FX-05 startup warning.

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
