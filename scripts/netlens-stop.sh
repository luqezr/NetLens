#!/bin/bash

# Stops all NetLens components (API + scanner) whether run via systemd or manually.
# Usage: sudo ./scripts/netlens-stop.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root: sudo $0" >&2
  exit 1
fi

echo "Stopping NetLens services (if installed)..."

# systemd units (ignore if not installed)
systemctl stop netlensscan.service 2>/dev/null || true
systemctl stop netlens.service 2>/dev/null || true

# Optional: disable autostart as well
if [[ "${1:-}" == "--disable" ]]; then
  systemctl disable netlensscan.service 2>/dev/null || true
  systemctl disable netlens.service 2>/dev/null || true
  echo "Disabled netlensscan.service and netlens.service at boot."
fi

echo "Killing any leftover NetLens processes..."
# Kill processes that reference the installed paths
pkill -f "/opt/netlens/server.js" 2>/dev/null || true
pkill -f "/opt/netlens/scanner_service.py" 2>/dev/null || true

# Kill processes that reference the repo paths (dev mode)
pkill -f "${REPO_ROOT}/server.js" 2>/dev/null || true
pkill -f "${REPO_ROOT}/scanner_service.py" 2>/dev/null || true

# If react dev server is running from this repo, user can stop it separately.

echo "Done. Current listeners on 5000/5443 (if any):"
ss -ltnp | grep -E ':(5000|5443)\b' || true
