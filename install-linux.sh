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

mkdir -p "$DEST"
install -m 0755 "$SRC_DIR/ifoxy_app" "$DEST/ifoxy_app"
ln -sf "$DEST/ifoxy_app" /usr/local/bin/ifoxy

echo "Installed: $DEST/ifoxy_app"
echo "Run it with: ifoxy  (it will ask for elevation via pkexec when needed)"
echo "Runtime needs: WebKitGTK 4.1, iproute2 (ip), iptables; GNOME proxy mode uses gsettings."
