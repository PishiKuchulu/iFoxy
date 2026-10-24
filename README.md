<div align="center">

<img src="docs/images/logo-horizontal.png" alt="iFoxy" width="360" />

# iFoxy

**Native VPN clients for Windows and Android — one Firefox account, two native apps.**
The Windows client is a single Rust binary with a real WebView2 interface and a userspace TCP/IP stack. The Android client is a native Kotlin / Jetpack Compose app. Both tunnel your traffic over HTTP/2.

[![Build Windows EXE](https://github.com/PishiKuchulu/iFoxy/actions/workflows/build-windows.yml/badge.svg)](https://github.com/PishiKuchulu/iFoxy/actions/workflows/build-windows.yml)
[![Android CI](https://github.com/PishiKuchulu/iFoxy/actions/workflows/android-ci.yml/badge.svg)](https://github.com/PishiKuchulu/iFoxy/actions/workflows/android-ci.yml)
![Rust](https://img.shields.io/badge/Rust-stable-orange?logo=rust)
![Kotlin](https://img.shields.io/badge/Kotlin-purple?logo=kotlin)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-blue?logo=windows)
![Android](https://img.shields.io/badge/Android-8.0%2B-green?logo=android)
![Status](https://img.shields.io/badge/status-experimental-yellow)

[English](#english) · [فارسی](#فارسی)

</div>

---

<a id="english"></a>

<img src="docs/images/fox-icon.png" alt="" width="48" /> **English**

## English

### What is iFoxy?

iFoxy is one project with native clients that share the same idea: sign in with a Firefox account and tunnel traffic over HTTP/2 CONNECT through Mozilla's Guardian/Firefox VPN edge. The desktop client (Windows and Linux) lives at the root of this repository; the Android client lives in [`android/`](android/).

### iFoxy for desktop (Windows & Linux)

The desktop client has two ways to protect your traffic:

- **Proxy Only.** The default mode. It starts a local proxy and points the system proxy at it (Windows registry / GNOME `gsettings`). No driver is needed.
- ⚠️ **Proxy Only caveat.** Applications that ignore the system proxy settings bypass the tunnel entirely in this mode and expose your real IP address. Use Full System mode when you need every application covered.
- **Full System.** Creates a virtual network adapter ([Wintun](https://www.wintun.net/) on Windows, a `/dev/net/tun` device on Linux) and captures IPv4 traffic at layer 3. Every TCP connection and DNS query on the machine goes through the tunnel. This mode needs administrator rights (root via pkexec on Linux), and a kill switch (WFP on Windows, iptables on Linux) blocks everything outside the tunnel while it is active.

Everything runs inside a single binary. The interface is HTML, CSS and vanilla JavaScript rendered by Microsoft Edge WebView2 on Windows and WebKitGTK on Linux, with no heavy frontend framework.

### Highlights

- 🧱 **Userspace TCP stack.** A full TCP state machine runs in user space: per-flow actors, reassembly queues, duplicate and overlapping segment trimming, fast retransmit, window tracking and FIN half-close.
- 🌐 **HTTP/2 CONNECT transport.** Traffic is multiplexed over encrypted HTTP/2 streams, which fits well through restrictive networks.
- 🔐 **Secrets stay local and encrypted.** Credentials are protected with Windows DPAPI with application-specific entropy (on Linux, with ChaCha20-Poly1305 and a per-user key file). Plaintext is never written to disk, and in-memory tokens are zeroized on drop.
- 🛡️ **Hardened control API.** The local API uses a per-session bearer token, strict Host header checks, cross-origin blocking, payload limits, timeouts and a Content-Security-Policy.
- 🧾 **Crash recovery.** A journal in `%APPDATA%\iFoxy\` restores routes and proxy settings after an unexpected exit.
- 🧹 **Redacting logs.** A rolling log file automatically redacts tokens, passwords and session secrets.
- 🚫 **Leak protection (in progress).** A WFP kill switch is implemented but not yet verified on a real Windows machine. See the status section below.

### Download

Tagged versions are published on the [**Releases**](https://github.com/PishiKuchulu/iFoxy/releases) page. Since v1.0.8, each release contains **all** clients:

- **Windows:** `ifoxy_app.exe`, with an `ifoxy_app.exe.sha256` file next to it so you can verify the download.
- **Linux:** `ifoxy-linux-x86_64.tar.gz` (the `ifoxy_app` binary plus `install-linux.sh`), with an `ifoxy-linux-x86_64.tar.gz.sha256` file next to it. Runtime needs: WebKitGTK 4.1, iproute2 and iptables.
- **Android:** `iFoxy-v<version>.apk` (Android 8.0 or newer), signed with the project release key. Signing certificate SHA-256: `f5381666261427b5f3c5345c79110c1aaede57b593b540d7aaa5ac481a340bee`.

The latest release is on the [**Releases**](https://github.com/PishiKuchulu/iFoxy/releases/latest) page.

For the newest Windows build between releases, go to the [**Actions**](https://github.com/PishiKuchulu/iFoxy/actions/workflows/build-windows.yml) tab, open the latest successful run of *Build Windows EXE* and download the `ifoxy_app-windows-x64` artifact.

### Build it yourself

Every build runs on GitHub's Windows runners. To build locally, you need:

- Windows 10 or 11, x64
- Rust with the MSVC toolchain (`rustup default stable-x86_64-pc-windows-msvc`)
- Visual Studio C++ Build Tools

```powershell
cargo test                 # run the test suite
.\build-release.ps1        # release build, output in .\dist\ifoxy_app.exe
.\install.ps1              # optional, elevated install into %ProgramFiles%\iFoxy
```

### How it works

```
  ┌──────────────┐   WebView2 IPC   ┌───────────────────┐
  │  UI (HTML/JS)│ ───────────────▶ │  Control API      │  loopback, token-gated
  └──────────────┘                  └────────┬──────────┘
                                             │
                    ┌────────────────────────┴──────────────────────┐
                    ▼                                               ▼
          ProxyOnly: local proxy                     Full System: Wintun adapter
          + WinINet system proxy                     → packet pump → userspace TCP
                    │                                  stack → per-flow actors
                    └────────────────┬──────────────────────────────┘
                                     ▼
                         HTTP/2 CONNECT over TLS
                                     ▼
                              Edge servers
```

The source is organized by responsibility:

| Folder | Responsibility |
|---|---|
| `src/vpn/` | Wintun adapter, userspace TCP stack, routing, DNS, kill switch |
| `src/tunnel/` | HTTP/2 streams, flow control, metrics |
| `src/auth/`, `src/crypto/` | Account sign-in, key derivation, Hawk authentication, DPAPI storage |
| `src/service/` | State machine, supervisor, token watchdog |
| `src/servers/` | Server discovery, latency probing, failover |
| `ui/` | The interface |

For a deeper look, read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Developer notes from the original project are in [`docs/DEVELOPER_NOTES.md`](docs/DEVELOPER_NOTES.md).

### Current limitations

Be aware of these before you rely on iFoxy:

- **Experimental.** This project is not production-ready. [`docs/FIX_TRACKER.md`](docs/FIX_TRACKER.md) lists the status of each item.
- **Kill switch not verified.** The WFP kill switch has been written but not tested on Windows yet.
- **Only IPv4 TCP and DNS are tunneled.** Other UDP traffic such as VoIP, games and WebRTC is rejected. IPv6 is blocked on the physical interface to prevent leaks.
- **Plain `http://` through the system proxy is refused.** Use HTTPS, or Full System mode.
- **Unsigned binary.** Windows SmartScreen may warn you when you first run `ifoxy_app.exe`.
- **Unofficial.** This is a third-party client. Parts of it reuse identifiers from official Mozilla clients and include a bot-challenge solver. Those parts can break at any time and may conflict with the terms of the service.

### Security

Please do not open public issues for security problems. Report them privately to the maintainers. Details are in [`docs/SECURITY.md`](docs/SECURITY.md).

### iFoxy for Android

**iFoxy for Android** lives in [`android/`](android/) — the same idea on mobile: a native Kotlin / Jetpack Compose client (based on FoxyVPN by Vauth, MIT) that signs in with a Firefox account (2FA supported) and tunnels the whole device over HTTP/2.

- Full-device TUN via hev-socks5-tunnel, plus a proxy-only mode (local SOCKS5/HTTP)
- Split tunneling, in-tunnel DNS over HTTPS and bootstrap resolver choices
- Upstream proxy chaining, TLS fragmentation, custom MTU, exit-location verification
- Guardian quota display, in-app logs, day / night / follow-system themes
- Hardened release line (current: see the latest release) — see [`android/CHANGELOG.md`](android/CHANGELOG.md)

Download the signed APK from the [Releases](https://github.com/PishiKuchulu/iFoxy/releases) page as described above. Features, build instructions and limitations are in [`android/README.md`](android/README.md).

---

<a id="فارسی"></a>

<div dir="rtl" align="right">

<img src="docs/images/fox-icon.png" alt="" width="48" /> **فارسی**

## فارسی

### iFoxy چیست؟

پروژه iFoxy دو کلاینت بومی دارد که یک ایده را دنبال می‌کنند: با حساب فایرفاکس وارد می‌شوید و ترافیک از طریق HTTP/2 CONNECT و لبه Guardian/Firefox VPN موزیلا تونل می‌شود. کلاینت دسکتاپ (ویندوز و لینوکس) در ریشه همین مخزن است و کلاینت اندروید در پوشه [`android/`](android/) قرار دارد.

### iFoxy برای دسکتاپ (ویندوز و لینوکس)

کلاینت دسکتاپ دو روش برای محافظت از ترافیک دارد:

- **فقط پروکسی (Proxy Only).** حالت پیش‌فرض. یک پروکسی محلی راه می‌اندازد و پروکسی سیستم را به آن وصل می‌کند (در ویندوز از طریق رجیستری و در لینوکس از طریق تنظیمات GNOME). به درایور اضافی نیاز ندارد.
- ⚠️ **هشدار حالت فقط پروکسی.** برنامه‌هایی که تنظیمات پروکسی سیستم را نادیده می‌گیرند در این حالت کاملاً از تونل عبور نمی‌کنند و آی‌پی واقعی شما آشکار می‌شود. برای پوشش همه برنامه‌ها از حالت تمام‌سیستمی استفاده کنید.
- **تونل کامل (Full System).** یک آداپتور شبکه مجازی می‌سازد (در ویندوز [Wintun](https://www.wintun.net/) و در لینوکس یک دیوایس ‎/dev/net/tun‎) و ترافیک IPv4 را در لایه ۳ می‌گیرد. در این حالت تمام اتصال‌های TCP و درخواست‌های DNS سیستم از تونل عبور می‌کنند و یک Kill Switch (در ویندوز WFP و در لینوکس iptables) جلوی نشت ترافیک بیرون از تونل را می‌گیرد. این حالت به دسترسی Administrator در ویندوز و root (از طریق pkexec) در لینوکس نیاز دارد.

همه‌چیز داخل یک فایل اجرایی واحد است. رابط کاربری با HTML، CSS و JavaScript ساده نوشته شده و در ویندوز توسط WebView2 مایکروسافت (همان موتور Edge) و در لینوکس توسط WebKitGTK نمایش داده می‌شود. فریم‌ورک سنگین فرانت‌اند ندارد.

### ویژگی‌های برجسته

- 🧱 **پشته TCP در فضای کاربر.** یک ماشین حالت کامل TCP داخل برنامه اجرا می‌شود. شامل actor برای هر جریان، صف بازسازی بسته‌ها، حذف بسته‌های تکراری و هم‌پوشان، fast retransmit، پیگیری پنجره و بستن نیم‌طرفه FIN است.
- 🌐 **انتقال HTTP/2 CONNECT.** ترافیک روی جریان‌های رمزشده HTTP/2 چندمولتی‌پلکس می‌شود. این روش در شبکه‌هایی با محدودیت شدید هم خوب کار می‌کند.
- 🔐 **اطلاعات محرمانه محلی و رمزشده.** اعتبارنامه‌ها در ویندوز با DPAPI و آنتروپی مخصوص کاربر و در لینوکس با رمزنگاری ChaCha20-Poly1305 و یک کلید مخصوص کاربر (با دسترسی 0600) محافظت می‌شوند. متن ساده هرگز روی دیسک نوشته نمی‌شود و توکن‌های داخل حافظه بعد از استفاده پاک می‌شوند.
- 🛡️ **API کنترل مقاوم‌سازی‌شده.** API محلی با توکن جلسه، بررسی سختگیرانه Host، مسدود کردن درخواست‌های cross-origin، محدودیت حجم داده، timeout و Content-Security-Policy محافظت می‌شود.
- 🧾 **بازیابی بعد از کرش.** یک journal در مسیر `%APPDATA%\iFoxy\` در ویندوز و `~/.config/iFoxy/` در لینوکس ذخیره می‌شود و مسیرها و تنظیمات پروکسی را بعد از خروج ناگهانی برمی‌گرداند.
- 🧹 **لاگ با حذف اطلاعات حساس.** فایل لاگ به‌صورت خودکار توکن‌ها، رمزها و اسرار جلسه را پنهان می‌کند.
- 🚫 **جلوگیری از نشت ترافیک.** حالت تونل کامل یک Kill Switch دارد که در ویندوز روی WFP و در لینوکس روی iptables پیاده‌سازی شده و تا وقتی تونل فعال است همه ترافیک بیرون از تونل را مسدود می‌کند.

### دانلود

نسخه‌های تگ‌خورده در صفحه [**Releases**](https://github.com/PishiKuchulu/iFoxy/releases) منتشر می‌شوند. از نسخه v1.0.8 به بعد، هر ریلیز شامل **هر سه** کلاینت است:

- **ویندوز:** فایل `ifoxy_app.exe` همراه با `ifoxy_app.exe.sha256` تا بتوانید صحت دانلود را بررسی کنید.
- **لینوکس:** فایل `ifoxy-linux-x86_64.tar.gz` (شامل باینری `ifoxy_app` و اسکریپت `install-linux.sh`) همراه با `ifoxy-linux-x86_64.tar.gz.sha256`. پیش‌نیازهای اجرا: کتابخانه WebKitGTK 4.1 و بسته‌های iproute2 و iptables.
- **اندروید:** فایل `iFoxy-v<version>.apk` (اندروید ۸٫۰ یا جدیدتر) که با کلید ریلیز پروژه امضا شده است. اثر انگشت گواهی امضا (SHA-256): `f5381666261427b5f3c5345c79110c1aaede57b593b540d7aaa5ac481a340bee`

آخرین نسخه را از [**صفحه ریلیزها**](https://github.com/PishiKuchulu/iFoxy/releases/latest) بگیرید.

برای تازه‌ترین بیلد ویندوز بین ریلیزها، به تب [**Actions**](https://github.com/PishiKuchulu/iFoxy/actions/workflows/build-windows.yml) بروید، آخرین اجرای موفق *Build Windows EXE* را باز کنید و آرتیفکت `ifoxy_app-windows-x64` را دانلود کنید.

### خودتان بسازید

هر بیلد روی سرورهای ویندوزی GitHub انجام می‌شود. برای ساخت محلی به این موارد نیاز دارید:

- ویندوز ۱۰ یا ۱۱ با معماری x64
- Rust با toolchain مربوط به MSVC (`rustup default stable-x86_64-pc-windows-msvc`)
- Visual Studio C++ Build Tools

```powershell
cargo test                 # اجرای تست‌ها
.\build-release.ps1        # بیلد نهایی، خروجی در .\dist\ifoxy_app.exe
.\install.ps1              # اختیاری، نصب با دسترسی Administrator در %ProgramFiles%\iFoxy
```

### نحوه کار

رابط کاربری از طریق WebView2 با یک API کنترلی محلی و امن صحبت می‌کند. این API بسته به حالت انتخابی، یا پروکسی محلی را فعال می‌کند یا آداپتور Wintun را. در حالت تونل کامل، بسته‌های IP به پشته TCP داخل برنامه می‌روند و هر جریان جداگانه از طریق HTTP/2 CONNECT روی TLS به سرورهای Edge فرستاده می‌شود.

ساختار سورس بر اساس وظیفه تقسیم شده است:

| پوشه | وظیفه |
|---|---|
| `src/vpn/` | آداپتور Wintun، پشته TCP، مسیریابی، DNS و Kill Switch |
| `src/tunnel/` | جریان‌های HTTP/2، کنترل جریان و متریک‌ها |
| `src/auth/`، `src/crypto/` | ورود به حساب، مشتق‌سازی کلید، احراز هویت Hawk و ذخیره‌سازی DPAPI |
| `src/service/` | ماشین حالت، supervisor و watchdog توکن |
| `src/servers/` | پیدا کردن سرورها، سنجش تأخیر و failover |
| `ui/` | رابط کاربری |

برای جزئیات بیشتر، فایل [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) را ببینید. یادداشت‌های توسعه‌دهنده در [`docs/DEVELOPER_NOTES.md`](docs/DEVELOPER_NOTES.md) قرار دارد.

### محدودیت‌های فعلی

قبل از استفاده، این موارد را در نظر داشته باشید:

- **آزمایشی.** این پروژه آماده تولید نیست. وضعیت هر بخش در [`docs/FIX_TRACKER.md`](docs/FIX_TRACKER.md) آمده است.
- **Kill Switch تأیید نشده.** کد Kill Switch نوشته شده، اما هنوز روی ویندوز تست نشده است.
- **فقط TCP و DNS با IPv4 از تونل عبور می‌کنند.** سایر ترافیک UDP مانند تماس صوتی، بازی و WebRTC رد می‌شود. IPv6 روی اینترفیس فیزیکی مسدود شده تا نشت نداشته باشد.
- **`http://` ساده از پروکسی سیستم رد می‌شود.** از HTTPS یا حالت Full System استفاده کنید.
- **فایل امضا نشده است.** ممکن است SmartScreen ویندوز در اولین اجرا هشدار بدهد.
- **غیررسمی.** این کلاینت شخص ثالث است. بخش‌هایی از آن از شناسه‌های کلاینت‌های رسمی Mozilla استفاده می‌کنند و یک حل‌کننده چالش ربات دارند. این بخش‌ها ممکن است هر لحظه از کار بیفتند و با شرایط سرویس مغایرت داشته باشند.

### امنیت

مشکلات امنیتی را در Issue عمومی گزارش نکنید. آن‌ها را به‌صورت خصوصی به نگهدارنده‌ها اطلاع دهید. جزئیات در [`docs/SECURITY.md`](docs/SECURITY.md) است.

### iFoxy برای اندروید

نسخه اندروید iFoxy در پوشه [`android/`](android/) همین مخزن قرار دارد؛ یک کلاینت بومی Kotlin/Jetpack Compose (بر پایه FoxyVPN ساخته Vauth، با مجوز MIT) که با حساب فایرفاکس (با پشتیبانی از تأیید دومرحله‌ای) وارد می‌شود و ترافیک کل دستگاه را از تونل HTTP/2 عبور می‌دهد.

- تونل کامل دستگاه با hev-socks5-tunnel، به‌علاوه حالت فقط پروکسی (SOCKS5/HTTP محلی)
- تونل‌بندی تقسیم‌شده (Split tunneling)، DNS داخل تونل با DoH و انتخاب‌های resolver راه‌انداز
- زنجیره پروکسی بالادستی، قطعه‌بندی TLS، MTU سفارشی و بررسی موقعیت خروجی
- نمایش سهمیه Guardian، لاگ داخل برنامه و تم‌های روز / شب / دنبال‌کردن سیستم
- خط ریلیز سخت‌سازی‌شده (نسخه فعلی: آخرین ریلیز را ببینید) — جزئیات در [`android/CHANGELOG.md`](android/CHANGELOG.md)

دانلود APK امضاشده از صفحه [Releases](https://github.com/PishiKuchulu/iFoxy/releases) انجام می‌شود (بخش دانلود در بالا). ویژگی‌ها، روش ساخت و محدودیت‌ها در [`android/README.md`](android/README.md) آمده است.

</div>

---

<div align="center">

<img src="docs/images/fox-icon.png" alt="iFoxy fox" width="32" /><br/>Made with Rust & Kotlin

</div>
