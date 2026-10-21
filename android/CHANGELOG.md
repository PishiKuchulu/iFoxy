# Changelog

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
  Apps can no longer bypass the VPN via `setAllowBypass` on Android 10+.
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
