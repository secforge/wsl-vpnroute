#!/bin/bash
set -euo pipefail

# wsl-vpnroute installer
#
# The userspace network binaries (wsl-gvproxy.exe / wsl-vm) are NOT shipped with
# this project. They are downloaded here from the upstream gvisor-tap-vsock
# release (Apache-2.0) and verified against pinned SHA-256 checksums before use.
# See NOTICE for attribution.

LIBDIR=/usr/local/lib/vpnroute
SBINDIR=/usr/local/sbin

# --- Pinned upstream release ------------------------------------------------
# https://github.com/containers/gvisor-tap-vsock/releases/tag/v0.8.9
GV_VERSION=v0.8.9
GV_BASEURL="https://github.com/containers/gvisor-tap-vsock/releases/download/${GV_VERSION}"

# asset name  ->  installed name
GV_PROXY_ASSET="gvproxy-windows.exe"   # Windows-side proxy  -> wsl-gvproxy.exe
GV_VM_ASSET="gvforwarder"              # Linux-side endpoint -> wsl-vm

# SHA-256 of the pinned assets (from the release's sha256sums file)
GV_PROXY_SHA256="a3b6915d8a976f5ed2bbba727af52c90c55b9d5e85f680b584c8a1c5d6b546bc"
GV_VM_SHA256="a62731c3e07e6d98b26043d236f4d03c9e2d464d75f1f3ec3670e5b2825eb6a6"
# ---------------------------------------------------------------------------

echo "Installing wsl-vpnroute..."

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: must run as root" >&2
  exit 1
fi

# The gvforwarder release asset is linux/amd64 only.
arch="$(uname -m)"
if [ "$arch" != "x86_64" ]; then
  echo "ERROR: unsupported architecture '$arch' (the gvforwarder release asset is linux/amd64 only)." >&2
  exit 1
fi

# jq is not used here, but the documented next step (vpnroute-discover) needs it,
# so fail now rather than after a "successful" install.
for tool in curl sha256sum go jq install; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: required tool '$tool' not found in PATH" >&2; exit 1; }
done

# fetch URL DEST SHA256 — download to DEST and verify checksum, abort on mismatch
fetch() {
  local url="$1" dest="$2" want="$3" got
  echo "  downloading $(basename "$dest")..."
  curl --fail --location --silent --show-error --output "$dest" "$url" \
    || { echo "ERROR: download failed: $url" >&2; exit 1; }
  got="$(sha256sum "$dest" | awk '{print $1}')"
  if [ "$got" != "$want" ]; then
    echo "ERROR: checksum mismatch for $(basename "$dest")" >&2
    echo "  expected: $want" >&2
    echo "  actual:   $got" >&2
    rm -f "$dest"
    exit 1
  fi
  echo "  checksum OK: $(basename "$dest")"
}

# --- Download + verify upstream binaries ------------------------------------
echo "Fetching upstream binaries (gvisor-tap-vsock ${GV_VERSION})..."
mkdir -p "$LIBDIR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch "${GV_BASEURL}/${GV_PROXY_ASSET}" "$tmp/wsl-gvproxy.exe" "$GV_PROXY_SHA256"
fetch "${GV_BASEURL}/${GV_VM_ASSET}"    "$tmp/wsl-vm"          "$GV_VM_SHA256"

install -m 755 "$tmp/wsl-vm"          "$LIBDIR/wsl-vm"
install -m 755 "$tmp/wsl-gvproxy.exe" "$LIBDIR/wsl-gvproxy.exe"
echo "Installed binaries to $LIBDIR"

# --- Build and install the monitor (our code) ------------------------------
echo "Building vpnroute-monitor..."
(cd monitor && go build -o vpnroute-monitor .)
[ -f monitor/vpnroute-monitor ] || { echo "ERROR: build did not produce monitor/vpnroute-monitor" >&2; exit 1; }
install -m 755 monitor/vpnroute-monitor "$SBINDIR/vpnroute-monitor"

# vpnroute-discover (one-shot script to detect VPN adapters)
install -m 755 vpnroute-discover "$SBINDIR/vpnroute-discover"

# systemd service
install -m 644 wsl-vpnroute.service /etc/systemd/system/wsl-vpnroute.service
systemctl daemon-reload
systemctl enable wsl-vpnroute
systemctl restart wsl-vpnroute

echo ""
echo "Done. If this is a first install, run: vpnroute-discover"
echo "This detects your TAP-Windows VPN adapters and writes /etc/vpnroute/vpn-adapters.conf"
