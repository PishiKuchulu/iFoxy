# Changelog — iFoxy desktop (Windows & Linux)

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
