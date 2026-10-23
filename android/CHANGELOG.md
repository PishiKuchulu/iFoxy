# Changelog

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
