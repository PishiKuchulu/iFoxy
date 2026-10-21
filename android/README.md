<div align="center">

# iFoxy - Unofficial Firefox VPN client

<p align="center">
  <img src="../docs/images/fox-icon.png" alt="iFoxy Logo" width="130"/>
</p>

![Android](https://img.shields.io/badge/Android-212121?style=for-the-badge&logo=android&logoColor=white)
![Kotlin](https://img.shields.io/badge/Kotlin-212121?style=for-the-badge&logo=kotlin&logoColor=white)
![Compose](https://img.shields.io/badge/Jetpack%20Compose-212121?style=for-the-badge&logo=android&logoColor=white)
![License](https://img.shields.io/badge/License_MIT-212121?style=for-the-badge)


*iFoxy signs in with a Firefox account, obtains a proxy pass from Mozilla's
Guardian service, and carries the whole device's traffic through Firefox VPN's
Fastly edge over an HTTP/2 tunnel. It is a native Kotlin app with a
Jetpack Compose (Material 3) UI.*

</div>

<br>

## 🔎 Features

- **System-wide VPN**
- **Firefox account sign-in**
- **Multiple Servers**
- **Split tunneling**
- **Private DNS by default**
- **Encrypted DNS (DNS over HTTPS)**
- **TLS fragmentation**
- **Custom Tunnel MTU**
- **Upstream proxy chaining**
- **Proxy-only mode**
- **Dark / light / follow-system theme**
- **Exit verification**
- **In-app logs**

<br>

## ⚠️ Known limitations

- **No UDP data plane** — only DNS is relayed (over DoH). QUIC/HTTP-3, games
  and WebRTC fall back to TCP or fail.
- **Kill switch** — the tunnel itself is fail-closed (it refuses to connect
  if it cannot capture IPv6), but for a strict system-level kill switch
  enable Android's *Always-on VPN* + *Block connections without VPN*.
- **Local proxies have no authentication** — keep the bind address on
  `127.0.0.1` unless you deliberately want an open proxy on your network;
  the app warns before enabling that.

<br>

## 📸 Screenshots
<div align="center">
  <img src="https://i.ibb.co/cK1L8wGk/90a25df7e3c6.jpg" alt="Screenshot 1" width="30%">
  <img src="https://i.ibb.co/tMff3B7C/198e4f622a58.jpg" alt="Screenshot 2" width="30%">
  <img src="https://i.ibb.co/G3V0CwCb/8524a888adee.jpg" alt="Screenshot 3" width="30%">
</div>

<br>

## 🚀 How to use?

1. **Get a Firefox account.** If you do not have one, create it for free at
   [accounts.firefox.com](https://accounts.firefox.com/signup).
2. **Install the APK** from the [Releases](https://github.com/pishi/ifoxy/releases)
   page.
3. **Sign in** with that account's email and password.
4. **Pick a location** and tap the power button.

> [!NOTE]
> **No subscription is required.** iFoxy runs on the free **50 GB of monthly
VPN traffic Mozilla includes with a Firefox account** for browser users, which
is the same allowance the Firefox browser's built-in VPN uses. Once the
allowance is used up for the month, connections stop working until it resets.

<br>

## 🗃 Requirements

- Android 8.0 (API 26) or newer
- JDK 17
- Android SDK 35 and NDK `26.1.10909125`
- `git` on `PATH`

<br>

## ⚙️ Build
* #### Clone Repository:
```bash
git clone https://github.com/pishi/ifoxy.git
cd ifoxy
   ```
* #### Build and Install:
```bash
./gradlew :app:assembleRelease --no-daemon
```
The Gradle wrapper is committed; do not substitute a system Gradle. The
native tun2socks dependency (hev-socks5-tunnel 2.17.1) is fetched on first
build and verified against a pinned commit before it is compiled.

<br>

### 📝 To-Do List
- [x] Improve stability.
- [x] Better Logo.
- [ ] HTTP/3 implementation (Not Planned Yet).

<br>

## ✍️ Acknowledgements

- [FoxyVPN](https://github.com/Vauth/FoxyVPN) by Vauth - the upstream Android client iFoxy for Android is based on (MIT)
- [firefox-vpn-client](https://github.com/UjuiUjuMandan/firefox-vpn-client) - the Go reference client this app is a port of
- [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) - the native tun2socks engine
- [Conscrypt](https://github.com/google/conscrypt) - ALPN-capable TLS on every supported API level

<br>

## 🛠 Contributing
Contributions are welcome! Feel free to submit a pull request or report an issue.

<br>

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
