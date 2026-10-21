<div align="center">

<img src="docs/images/logo-horizontal.png" alt="iFoxy" width="360" />

# iFoxy for Windows

**A native Windows VPN client written in Rust.**
One binary. A real WebView2 interface. A userspace TCP/IP stack that tunnels your traffic over HTTP/2.

[![Build Windows EXE](https://github.com/PishiKuchulu/iFoxy/actions/workflows/build-windows.yml/badge.svg)](https://github.com/PishiKuchulu/iFoxy/actions/workflows/build-windows.yml)
![Rust](https://img.shields.io/badge/Rust-stable-orange?logo=rust)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-blue?logo=windows)
![Status](https://img.shields.io/badge/status-experimental-yellow)

[English](#english) · [فارسی](#فارسی)

</div>

---

<a id="english"></a>

<img src="docs/images/fox-icon.png" alt="" width="48" /> **English**

## English

### What is iFoxy?

iFoxy is a desktop VPN client for Windows. It has two ways to protect your traffic:

- **Proxy Only.** The default mode. It starts a local proxy and points the Windows system proxy at it. No driver is needed.
- **Full System.** Creates a virtual network adapter with [Wintun](https://www.wintun.net/) and captures IPv4 traffic at layer 3. Every TCP connection and DNS query on the machine goes through the tunnel. This mode needs administrator rights.

Everything runs inside a single `ifoxy_app.exe`. The interface is HTML, CSS and vanilla JavaScript rendered by Microsoft Edge WebView2, with no heavy frontend framework.

### Highlights

- 🧱 **Userspace TCP stack.** A full TCP state machine runs in user space: per-flow actors, reassembly queues, duplicate and overlapping segment trimming, fast retransmit, window tracking and FIN half-close.
- 🌐 **HTTP/2 CONNECT transport.** Traffic is multiplexed over encrypted HTTP/2 streams, which fits well through restrictive networks.
- 🔐 **Secrets stay local and encrypted.** Credentials are protected with Windows DPAPI, using user-specific entropy. Plaintext is never written to disk, and in-memory tokens are zeroized on drop.
- 🛡️ **Hardened control API.** The local API uses a per-session bearer token, strict Host header checks, cross-origin blocking, payload limits, timeouts and a Content-Security-Policy.
- 🧾 **Crash recovery.** A journal in `%APPDATA%\iFoxy\` restores routes and proxy settings after an unexpected exit.
- 🧹 **Redacting logs.** A rolling log file automatically redacts tokens, passwords and session secrets.
- 🚫 **Leak protection (in progress).** A WFP kill switch is implemented but not yet verified on a real Windows machine. See the status section below.

### Download

Go to the [**Actions**](https://github.com/PishiKuchulu/iFoxy/actions/workflows/build-windows.yml) tab and open the latest successful run. Download the `ifoxy_app-windows-x64` artifact. Each build also includes a `.sha256` file, so you can check the integrity of the download.

Tagged versions (for example `v0.1.0`) are published on the [**Releases**](https://github.com/PishiKuchulu/iFoxy/releases) page automatically.

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

This repository also contains **iFoxy for Android** in [`android/`](android/) — the same idea on mobile: a native Kotlin/Jetpack Compose client (based on FoxyVPN by Vauth, MIT) that signs in with a Firefox account and tunnels the whole device over HTTP/2. See [`android/README.md`](android/README.md) for features, build instructions and its changelog.

---

<a id="فارسی"></a>

<div dir="rtl" align="right">

<img src="docs/images/fox-icon.png" alt="" width="48" /> **فارسی**

## فارسی

### iFoxy چیست؟

iFoxy یک کلاینت VPN دسکتاپ برای ویندوز است. دو روش برای محافظت از ترافیک دارد:

- **فقط پروکسی (Proxy Only).** حالت پیش‌فرض. یک پروکسی محلی راه می‌اندازد و پروکسی سیستم ویندوز را به آن وصل می‌کند. به درایور اضافی نیاز ندارد.
- **تونل کامل (Full System).** با [Wintun](https://www.wintun.net/) یک آداپتور شبکه مجازی می‌سازد و ترافیک IPv4 را در لایه ۳ می‌گیرد. در این حالت تمام اتصال‌های TCP و درخواست‌های DNS سیستم از تونل عبور می‌کنند. این حالت به دسترسی Administrator نیاز دارد.

همه‌چیز داخل یک فایل `ifoxy_app.exe` است. رابط کاربری با HTML، CSS و JavaScript ساده نوشته شده و توسط WebView2 مایکروسافت (همان موتور Edge) نمایش داده می‌شود. فریم‌ورک سنگین فرانت‌اند ندارد.

### ویژگی‌های برجسته

- 🧱 **پشته TCP در فضای کاربر.** یک ماشین حالت کامل TCP داخل برنامه اجرا می‌شود. شامل actor برای هر جریان، صف بازسازی بسته‌ها، حذف بسته‌های تکراری و هم‌پوشان، fast retransmit، پیگیری پنجره و بستن نیم‌طرفه FIN است.
- 🌐 **انتقال HTTP/2 CONNECT.** ترافیک روی جریان‌های رمزشده HTTP/2 چندمولتی‌پلکس می‌شود. این روش در شبکه‌هایی با محدودیت شدید هم خوب کار می‌کند.
- 🔐 **اطلاعات محرمانه محلی و رمزشده.** اعتبارنامه‌ها با DPAPI ویندوز و با آنتروپی مخصوص کاربر محافظت می‌شوند. متن ساده هرگز روی دیسک نوشته نمی‌شود و توکن‌های داخل حافظه بعد از استفاده پاک می‌شوند.
- 🛡️ **API کنترل مقاوم‌سازی‌شده.** API محلی با توکن جلسه، بررسی سختگیرانه Host، مسدود کردن درخواست‌های cross-origin، محدودیت حجم داده، timeout و Content-Security-Policy محافظت می‌شود.
- 🧾 **بازیابی بعد از کرش.** یک journal در مسیر `%APPDATA%\iFoxy\` ذخیره می‌شود و مسیرها و تنظیمات پروکسی را بعد از خروج ناگهانی برمی‌گرداند.
- 🧹 **لاگ با حذف اطلاعات حساس.** فایل لاگ به‌صورت خودکار توکن‌ها، رمزها و اسرار جلسه را پنهان می‌کند.
- 🚫 **جلوگیری از نشت ترافیک (در حال توسعه).** Kill Switch مبتنی بر WFP نوشته شده، اما هنوز روی یک ویندوز واقعی تأیید نشده است. جزئیات را در بخش وضعیت پروژه ببینید.

### دانلود

به تب [**Actions**](https://github.com/PishiKuchulu/iFoxy/actions/workflows/build-windows.yml) بروید و آخرین اجرای موفق را باز کنید. فایل `ifoxy_app-windows-x64` را دانلود کنید. همراه هر بیلد یک فایل `.sha256` هم هست تا بتوانید صحت فایل را بررسی کنید.

نسخه‌هایی که تگ می‌خورند (مثلاً `v0.1.0`) خودکار در صفحه [**Releases**](https://github.com/PishiKuchulu/iFoxy/releases) منتشر می‌شوند.

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

نسخه اندروید iFoxy هم در همین مخزن، در پوشه [`android/`](android/) قرار دارد؛ یک کلاینت بومی Kotlin/Jetpack Compose (بر پایه FoxyVPN ساخته Vauth، با مجوز MIT) که با حساب فایرفاکس وارد می‌شود و ترافیک کل دستگاه را از تونل HTTP/2 عبور می‌دهد. جزئیات در [`android/README.md`](android/README.md) است.

</div>

---

<div align="center">

<img src="docs/images/fox-icon.png" alt="iFoxy fox" width="32" /><br/>Made with Rust

</div>
