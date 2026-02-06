#!/usr/bin/env bash
set -euo pipefail

# NetLens in-place updater
# - Refreshes application files in /opt/netlens
# - Preserves MongoDB data (does not touch the database)
# - Preserves /opt/netlens/config.env, /opt/netlens/logs/, and /opt/netlens/venv/
# - Rebuilds the React frontend so changes show up immediately

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "ERROR: Please run as root (sudo ./update.sh)" >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/opt/netlens"

PULL_LATEST="false"
if [[ "${1:-}" == "--pull" ]]; then
  PULL_LATEST="true"
fi

if [[ ! -d "$DEST_DIR" ]]; then
  echo "ERROR: $DEST_DIR not found. Run ./install.sh first." >&2
  exit 1
fi

# Basic sanity check: avoid syncing the wrong folder into /opt/netlens.
if [[ ! -f "$SRC_DIR/server.js" || ! -f "$SRC_DIR/scanner_service.py" ]]; then
  echo "ERROR: $SRC_DIR does not look like a NetLens source folder (missing server.js/scanner_service.py)." >&2
  echo "Run update.sh from the freshly downloaded NetLens repo folder." >&2
  exit 1
fi

if [[ "$PULL_LATEST" == "true" ]]; then
  if command -v git >/dev/null 2>&1 && [[ -d "$SRC_DIR/.git" ]]; then
    echo "→ Pulling latest changes in $SRC_DIR"
    git -C "$SRC_DIR" fetch --all --prune
    # Pull current branch (best-effort; do not block upgrade if git fails)
    git -C "$SRC_DIR" pull --ff-only || true
  else
    echo "WARN: --pull requested, but $SRC_DIR is not a git checkout. Skipping git pull." >&2
  fi
fi

echo "→ Stopping services (netlensscan, netlens)"
systemctl stop netlensscan.service >/dev/null 2>&1 || true
systemctl stop netlens.service >/dev/null 2>&1 || true

# Preserve config.env if present
TMP_CONF=""
if [[ -f "$DEST_DIR/config.env" ]]; then
  TMP_CONF="$(mktemp)"
  cp -f "$DEST_DIR/config.env" "$TMP_CONF"
fi

echo "→ Syncing application files to $DEST_DIR (preserving config/logs/venv/certs)"
# rsync is preferred; fall back to cp if not available.
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete \
    --exclude 'config.env' \
    --exclude 'logs/' \
    --exclude 'venv/' \
    --exclude 'certs/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    --exclude 'node_modules/' \
    --exclude 'frontend/node_modules/' \
    --exclude 'frontend/build/' \
    "$SRC_DIR/" "$DEST_DIR/"
else
  echo "WARN: rsync not found; using cp (may leave stale files behind)." >&2
  cp -a "$SRC_DIR/." "$DEST_DIR/"
  rm -rf "$DEST_DIR/frontend/build" || true
fi

if [[ -n "$TMP_CONF" ]]; then
  cp -f "$TMP_CONF" "$DEST_DIR/config.env"
  rm -f "$TMP_CONF"
fi

# Update systemd unit files if present in repo
if [[ -f "$SRC_DIR/netlens.service" ]]; then
  echo "→ Updating systemd unit: netlens.service"
  cp -f "$SRC_DIR/netlens.service" /etc/systemd/system/netlens.service
fi
if [[ -f "$SRC_DIR/netlensscan.service" ]]; then
  echo "→ Updating systemd unit: netlensscan.service"
  cp -f "$SRC_DIR/netlensscan.service" /etc/systemd/system/netlensscan.service
fi
systemctl daemon-reload >/dev/null 2>&1 || true

# Ensure venv exists and deps are installed
if [[ ! -x "$DEST_DIR/venv/bin/python" ]]; then
  echo "→ Creating Python venv"
  python3 -m venv "$DEST_DIR/venv"
fi

echo "→ Installing Python dependencies (preserves DB)"
"$DEST_DIR/venv/bin/pip" install --upgrade pip >/dev/null
"$DEST_DIR/venv/bin/pip" install -r "$DEST_DIR/requirements.txt"

# Install Node deps (API)
if [[ -f "$DEST_DIR/package.json" ]]; then
  echo "→ Installing Node dependencies (API)"
  cd "$DEST_DIR"
  if [[ -f package-lock.json ]]; then
    npm ci --no-audit --no-fund || npm install --no-audit --no-fund
  else
    npm install --no-audit --no-fund
  fi
fi

# Build frontend
if [[ -f "$DEST_DIR/frontend/package.json" ]]; then
  echo "→ Installing Node dependencies + building frontend"
  cd "$DEST_DIR/frontend"
  if [[ -f package-lock.json ]]; then
    npm ci --no-audit --no-fund || npm install --no-audit --no-fund
  else
    npm install --no-audit --no-fund
  fi

  # Keep the current UI working if the build fails.
  BUILD_DIR="$DEST_DIR/frontend/build"
  BACKUP_DIR=""
  if [[ -d "$BUILD_DIR" ]]; then
    BACKUP_DIR="$DEST_DIR/frontend/build.prev.$(date +%Y%m%d%H%M%S)"
    mv "$BUILD_DIR" "$BACKUP_DIR"
  fi

  if npm run build; then
    rm -rf "$BACKUP_DIR" >/dev/null 2>&1 || true
  else
    echo "ERROR: Frontend build failed." >&2
    if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then
      echo "→ Restoring previous frontend build"
      rm -rf "$BUILD_DIR" || true
      mv "$BACKUP_DIR" "$BUILD_DIR"
    fi
    exit 1
  fi
fi

# Ensure scripts are executable
chmod +x "$DEST_DIR/scanner_service.py" >/dev/null 2>&1 || true

# Fix permissions on logs directory (scanner might run as root, API as netlens)
mkdir -p "$DEST_DIR/logs" || true
chown -R netlens:netlens "$DEST_DIR/logs" >/dev/null 2>&1 || true

echo "→ Starting services"
systemctl start netlensscan.service
systemctl start netlens.service || true

echo "→ Done. Status:"
systemctl --no-pager --full status netlensscan.service | sed -n '1,12p' || true
systemctl --no-pager --full status netlens.service | sed -n '1,12p' || true

echo "\nTip: Tail logs"
echo "  journalctl -u netlensscan -f"
echo "  journalctl -u netlens -f"
