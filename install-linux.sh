#!/bin/sh
# iFoxy for Linux — install to /opt/ifoxy (administrator-owned, the
# location the elevated binary should live in) and put a launcher on PATH.
set -e

SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEST=/opt/ifoxy

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo ./install-linux.sh"
    exit 1
fi

# Verify the release tarball when its SHA-256 sidecar is available (the
# sidecar is a separate release asset holding a bare hash; place it next to
# the tarball). A mismatch aborts the install; a missing sidecar only warns,
# because the tarball itself contains just the binary and this script.
SIDECAR_DIR=""
for d in "$SRC_DIR" "$SRC_DIR/.."; do
    if [ -f "$d/ifoxy-linux-x86_64.tar.gz.sha256" ]; then
        SIDECAR_DIR=$(CDPATH= cd -- "$d" && pwd)
        break
    fi
done
if [ -n "$SIDECAR_DIR" ] && [ -f "$SIDECAR_DIR/ifoxy-linux-x86_64.tar.gz" ]; then
    EXPECTED=$(tr -d ' \t\r\n' < "$SIDECAR_DIR/ifoxy-linux-x86_64.tar.gz.sha256")
    if echo "$EXPECTED  $SIDECAR_DIR/ifoxy-linux-x86_64.tar.gz" | sha256sum -c - >/dev/null 2>&1; then
        echo "SHA-256 verified for ifoxy-linux-x86_64.tar.gz"
    else
        echo "SHA-256 mismatch for ifoxy-linux-x86_64.tar.gz - refusing to install." >&2
        exit 1
    fi
else
    echo "WARNING: ifoxy-linux-x86_64.tar.gz.sha256 not found next to the tarball - installing WITHOUT integrity verification." >&2
fi

mkdir -p "$DEST"
install -m 0755 "$SRC_DIR/ifoxy_app" "$DEST/ifoxy_app"
ln -sf "$DEST/ifoxy_app" /usr/local/bin/ifoxy

echo "Installed: $DEST/ifoxy_app"
echo "Run it with: ifoxy  (it will ask for elevation via pkexec when needed)"
echo "Runtime needs: WebKitGTK 4.1, iproute2 (ip), iptables; GNOME proxy mode uses gsettings."
