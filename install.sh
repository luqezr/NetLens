#!/bin/bash

# NetLens Installation Script (Debian/Ubuntu)
# Installs and configures the NetLens network monitoring service

set -euo pipefail

prompt_yes_no() {
    local prompt="$1"
    local default_answer="${2:-}"
    local answer=""

    while true; do
        if [[ "$default_answer" == "y" ]]; then
            read -r -p "$prompt [Y/n]: " answer
            answer="${answer:-y}"
        elif [[ "$default_answer" == "n" ]]; then
            read -r -p "$prompt [y/N]: " answer
            answer="${answer:-n}"
        else
            read -r -p "$prompt [y/n]: " answer
        fi

        case "${answer,,}" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

detect_python_bin() {
    if command -v python3 >/dev/null 2>&1; then
        echo "python3"
        return 0
    fi
    if command -v python >/dev/null 2>&1; then
        echo "python"
        return 0
    fi
    return 1
}

detect_pip_bin() {
    if command -v pip3 >/dev/null 2>&1; then
        echo "pip3"
        return 0
    fi
    if command -v pip >/dev/null 2>&1; then
        echo "pip"
        return 0
    fi
    return 1
}

generate_urlsafe_password() {
    # URL-safe for MongoDB connection URIs without needing encoding.
    local py
    py="$(detect_python_bin || true)"
    if [[ -z "$py" ]]; then
        echo "ERROR: python3/python not found (required to generate secrets)." >&2
        exit 1
    fi
    "$py" - <<'PY'
import secrets
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
print("".join(secrets.choice(alphabet) for _ in range(40)))
PY
}

detect_mongo_shell() {
    if command -v mongosh >/dev/null 2>&1; then
        echo "mongosh"
        return 0
    fi
    if command -v mongo >/dev/null 2>&1; then
        echo "mongo"
        return 0
    fi
    return 1
}

detect_mongo_service() {
    if systemctl list-unit-files --no-pager 2>/dev/null | grep -qE '^mongod\.service\s'; then
        echo "mongod"
        return 0
    fi
    if systemctl list-unit-files --no-pager 2>/dev/null | grep -qE '^mongodb\.service\s'; then
        echo "mongodb"
        return 0
    fi
    return 1
}

try_install_mongodb() {
    # MongoDB packages vary by distro/repo. Try common names.
    if dpkg -s mongodb-org >/dev/null 2>&1; then
        return 0
    fi

    set +e
    apt-get install -y mongodb >/dev/null 2>&1
    local rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
        return 0
    fi

    set +e
    apt-get install -y mongodb-server >/dev/null 2>&1
    rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
        return 0
    fi

    return 1
}

echo "====================================="
echo "NetLens Installation"
echo "====================================="

preflight_check() {
    local missing=()

    if ! command -v systemctl >/dev/null 2>&1; then
        missing+=("systemctl")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "ERROR: Missing required commands: ${missing[*]}" >&2
        echo "Install them and re-run this installer." >&2
        exit 1
    fi
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo ./install.sh)"
    exit 1
fi

echo "Select your Linux distribution family:"
echo "1) Debian/Ubuntu-based (apt)"
echo "2) Arch Linux-based (pacman)"
read -r -p "Enter choice [1]: " DISTRO_CHOICE
DISTRO_CHOICE="${DISTRO_CHOICE:-1}"

PKG_MGR="apt"
if [[ "$DISTRO_CHOICE" == "2" ]]; then
    PKG_MGR="pacman"
fi

echo "Updating system packages..."
if [[ "$PKG_MGR" == "apt" ]]; then
    apt-get update
    if prompt_yes_no "Run full system upgrade (apt-get upgrade)?" "y"; then
        apt-get upgrade -y
    else
        echo "Skipping system upgrade."
    fi
else
    if ! command -v pacman >/dev/null 2>&1; then
        echo "ERROR: Arch option selected but pacman not found." >&2
        exit 1
    fi
    if prompt_yes_no "Run full system upgrade (pacman -Syu)?" "y"; then
        pacman -Syu --noconfirm
    else
        echo "Skipping system upgrade; syncing package databases only (pacman -Sy)."
        pacman -Sy --noconfirm
    fi
fi

echo "Installing OS dependencies..."
if [[ "$PKG_MGR" == "apt" ]]; then
    apt-get install -y \
        python3 \
        python3-venv \
        python3-pip \
        nmap \
        tcpdump \
        nodejs \
        npm \
        git \
        curl \
        openssl
else
    pacman -S --noconfirm --needed \
        python \
        python-pip \
        nmap \
        tcpdump \
        nodejs \
        npm \
        git \
        curl \
        openssl

    # Try to install MongoDB + shell on Arch if available.
    pacman -S --noconfirm --needed mongodb mongosh >/dev/null 2>&1 || true
fi

echo "Verifying installed dependencies..."
missing_deps=()
PYTHON_BIN="$(detect_python_bin || true)"
PIP_BIN="$(detect_pip_bin || true)"
if [[ -z "$PYTHON_BIN" ]]; then missing_deps+=("python3/python"); fi
if [[ -z "$PIP_BIN" ]]; then missing_deps+=("pip3/pip"); fi
for cmd in node npm nmap tcpdump git curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing_deps+=("$cmd")
    fi
done
if [[ ${#missing_deps[@]} -gt 0 ]]; then
    echo "ERROR: Missing expected commands after dependency install: ${missing_deps[*]}" >&2
    echo "Please install them manually and re-run this installer." >&2
    exit 1
fi

echo "Checking MongoDB installation..."
if ! command -v mongod >/dev/null 2>&1 && ! systemctl list-unit-files --no-pager 2>/dev/null | grep -qE '^(mongod|mongodb)\.service\s'; then
    echo "MongoDB not detected. Attempting to install a MongoDB package from apt repositories..."
    if ! try_install_mongodb; then
        echo ""
        echo "ERROR: MongoDB is not installed and could not be installed via apt." >&2
        echo "Install MongoDB (server + shell) and re-run this installer." >&2
        echo "Docs: https://www.mongodb.com/docs/manual/administration/install-on-linux/" >&2
        exit 1
    fi
fi

HTTP_PORT_DEFAULT="5000"
HTTPS_PORT_DEFAULT="5443"
MONGO_PORT_DEFAULT="27017"
CORS_PORT_DEFAULT="3000"

read -r -p "HTTP port for NetLens API [${HTTP_PORT_DEFAULT}]: " HTTP_PORT
HTTP_PORT="${HTTP_PORT:-$HTTP_PORT_DEFAULT}"

read -r -p "HTTPS port for NetLens API [${HTTPS_PORT_DEFAULT}]: " HTTPS_PORT
HTTPS_PORT="${HTTPS_PORT:-$HTTPS_PORT_DEFAULT}"

read -r -p "MongoDB port [${MONGO_PORT_DEFAULT}]: " MONGO_PORT
MONGO_PORT="${MONGO_PORT:-$MONGO_PORT_DEFAULT}"

read -r -p "Frontend (CORS) port [${CORS_PORT_DEFAULT}]: " CORS_PORT
CORS_PORT="${CORS_PORT:-$CORS_PORT_DEFAULT}"

ENABLE_HTTPS="false"
TLS_DIR="/opt/netlens/certs"
TLS_CERT_PATH="${TLS_DIR}/netlens.crt"
TLS_KEY_PATH="${TLS_DIR}/netlens.key"

if prompt_yes_no "Generate a self-signed OpenSSL certificate for HTTPS?" "y"; then
    ENABLE_HTTPS="true"
    read -r -p "Certificate common name (CN) [localhost]: " TLS_CN
    TLS_CN="${TLS_CN:-localhost}"

    mkdir -p "$TLS_DIR"
    chmod 700 "$TLS_DIR"

    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
        -subj "/CN=${TLS_CN}" \
        -keyout "$TLS_KEY_PATH" \
        -out "$TLS_CERT_PATH"

    chmod 600 "$TLS_KEY_PATH" "$TLS_CERT_PATH"
fi

# Verify required project files exist before proceeding.
echo "Verifying installer inputs..."
required_files=(
    "server.js"
    "scanner_service.py"
    "package.json"
    "requirements.txt"
    "netlensscan.service"
    "netlens.service"
    "scripts/netlens-stop.sh"
    "scripts/netlens-manager.sh"
)
missing_files=()
for f in "${required_files[@]}"; do
    if [[ ! -f "$f" ]]; then
        missing_files+=("$f")
    fi
done
if [[ ${#missing_files[@]} -gt 0 ]]; then
    echo "ERROR: Missing required files in this repo: ${missing_files[*]}" >&2
    echo "Run this installer from the NetLens repo root." >&2
    exit 1
fi

# Create application directory
echo "Creating application directory..."
mkdir -p /opt/netlens
mkdir -p /opt/netlens/logs
mkdir -p /opt/netlens/database

# Set proper permissions for logs directory
chmod 755 /opt/netlens/logs

# Copy application files
echo "Copying application files..."
cp -r ./* /opt/netlens/

# Install Python dependencies
echo "Installing Python packages..."
cd /opt/netlens

PY_BIN="python3"
if ! command -v "$PY_BIN" >/dev/null 2>&1; then
    PY_BIN="python"
fi

echo "Creating virtual environment at /opt/netlens/venv ..."
"$PY_BIN" -m venv /opt/netlens/venv

echo "Installing Python packages into venv..."
/opt/netlens/venv/bin/python -m pip install --upgrade pip
/opt/netlens/venv/bin/python -m pip install -r requirements.txt

# Install Node.js dependencies
echo "Installing Node.js packages..."
npm install

# Create user for service
echo "Creating service user..."
if ! id -u netlens > /dev/null 2>&1; then
    useradd -r -s /bin/false netlens
fi

# Set permissions
echo "Setting permissions..."
chown -R netlens:netlens /opt/netlens
chmod +x /opt/netlens/scanner_service.py

# If HTTPS was enabled, ensure TLS files are readable by the service user.
# Keep the private key owned by root to prevent accidental modification.
if [[ "${ENABLE_HTTPS}" == "true" ]]; then
    if [[ -d "${TLS_DIR}" ]]; then
        chown root:netlens "${TLS_DIR}" 2>/dev/null || true
        chmod 750 "${TLS_DIR}" 2>/dev/null || true

        if [[ -f "${TLS_KEY_PATH}" ]]; then
            chown root:netlens "${TLS_KEY_PATH}" 2>/dev/null || true
            chmod 640 "${TLS_KEY_PATH}" 2>/dev/null || true
        fi
        if [[ -f "${TLS_CERT_PATH}" ]]; then
            chown root:netlens "${TLS_CERT_PATH}" 2>/dev/null || true
            chmod 644 "${TLS_CERT_PATH}" 2>/dev/null || true
        fi
    fi
fi

# Configure MongoDB
echo "Starting MongoDB service..."
MONGO_SERVICE=""
if MONGO_SERVICE=$(detect_mongo_service); then
    systemctl enable "$MONGO_SERVICE"
    systemctl start "$MONGO_SERVICE"
else
    echo "WARNING: Could not detect mongodb/mongod systemd service name." >&2
    echo "Attempting to proceed; ensure MongoDB is running." >&2
fi

# Wait for MongoDB to start
sleep 5

APP_DB="netlens"
APP_DB_PASS="$(generate_urlsafe_password)"
APP_DB_USER=""
MONGO_USER_CREATED="no"
MONGO_ADMIN_CREATED="no"

echo ""
echo "MongoDB Configuration:"
echo "  NetLens needs a MongoDB user for the application database."
echo "  All credentials will be auto-generated and saved to summary.txt"
echo ""

MONGO_SHELL=""
if ! MONGO_SHELL=$(detect_mongo_shell); then
        echo "WARNING: MongoDB shell (mongosh/mongo) not found." >&2
        echo "Skipping MongoDB user creation. Configure manually later." >&2
        MONGO_SHELL=""
fi

if [[ -n "$MONGO_SHELL" ]]; then
    # Ask if MongoDB has authentication enabled
    MONGO_AUTH_ENABLED="no"
    MONGO_ADMIN_USER=""
    MONGO_ADMIN_PASS=""
    MONGO_AUTH_DB="admin"
    
    if prompt_yes_no "Does MongoDB require authentication?" "n"; then
        MONGO_AUTH_ENABLED="yes"
        echo ""
        echo "NOTE: Please provide your EXISTING MongoDB admin credentials."
        echo "      NetLens will use them to create the application user."
        echo "      The user must have 'userAdmin' or 'userAdminAnyDatabase' role."
        echo ""
        read -r -p "MongoDB admin username: " MONGO_ADMIN_USER
        read -r -s -p "MongoDB admin password: " MONGO_ADMIN_PASS
        echo ""
        read -r -p "MongoDB authentication database [admin]: " MONGO_AUTH_DB
        MONGO_AUTH_DB="${MONGO_AUTH_DB:-admin}"
        
        # Test credentials before proceeding
        echo "Testing MongoDB credentials..."
        test_result=$("$MONGO_SHELL" --quiet \
            --username "$MONGO_ADMIN_USER" \
            --password "$MONGO_ADMIN_PASS" \
            --authenticationDatabase "$MONGO_AUTH_DB" \
            --eval "db.runCommand({ connectionStatus: 1 }).authInfo" 2>&1)
        
        if echo "$test_result" | grep -q "MongoServerError\|Authentication failed"; then
            echo "ERROR: Cannot authenticate to MongoDB with provided credentials" >&2
            echo "Please check:" >&2
            echo "  - Username: $MONGO_ADMIN_USER" >&2
            echo "  - Authentication database: $MONGO_AUTH_DB" >&2
            echo "  - Password (hidden)" >&2
            echo "" >&2
            echo "Output: $test_result" >&2
            exit 1
        fi
        echo "✅ MongoDB authentication successful"
        
        # Check if user has privileges to create users
        echo "Checking user privileges..."
        roles_result=$("$MONGO_SHELL" --quiet \
            --username "$MONGO_ADMIN_USER" \
            --password "$MONGO_ADMIN_PASS" \
            --authenticationDatabase "$MONGO_AUTH_DB" \
            --eval "db.getSiblingDB('admin').getUser('${MONGO_ADMIN_USER}').roles" 2>&1)
        
        if echo "$roles_result" | grep -qE "userAdmin|root|dbOwner"; then
            echo "✅ User has sufficient privileges"
        else
            echo "⚠️  WARNING: User might not have privileges to create users" >&2
            echo "   Required roles: userAdmin, userAdminAnyDatabase, root, or dbOwner" >&2
            echo "   User roles: $roles_result" >&2
            if ! prompt_yes_no "Continue anyway?" "n"; then
                exit 1
            fi
        fi
    else
        # No auth currently - create admin user first, then app user
        echo ""
        echo "Creating MongoDB admin user for future administration..."
        MONGO_ADMIN_USER="netLensAdmin"
        MONGO_ADMIN_PASS="$(generate_urlsafe_password)"
        MONGO_AUTH_DB="admin"
        
        create_admin_js=$(cat <<JS
db = db.getSiblingDB("admin");
const user = "${MONGO_ADMIN_USER}";
const pwd = "${MONGO_ADMIN_PASS}";
try {
  const existing = db.getUser(user);
  if (existing) {
    print('Admin user already exists: ' + user);
  } else {
    db.createUser({ 
      user: user, 
      pwd: pwd, 
      roles: [{ role: 'userAdminAnyDatabase', db: 'admin' }, { role: 'dbAdminAnyDatabase', db: 'admin' }] 
    });
    print('Created admin user: ' + user);
  }
} catch(e) {
  print('Created admin user: ' + user);
}
JS
)
        
        if "$MONGO_SHELL" --quiet --eval "${create_admin_js}" 2>&1 | grep -q "Created admin user"; then
            echo "✅ Created MongoDB admin: ${MONGO_ADMIN_USER}"
            MONGO_ADMIN_CREATED="yes"
            MONGO_AUTH_ENABLED="yes"
        else
            echo "⚠️  Admin user may already exist or creation skipped"
            MONGO_AUTH_ENABLED="yes"
        fi
    fi

    echo "Creating MongoDB application user (auto-generated credentials)..."
    APP_DB_USER=""
create_mongo_user() {
    local user="$1"
    local pwd="$2"
    local db="$APP_DB"
    
    # Escape any special characters in password for JavaScript
    local escaped_pwd="${pwd//\\/\\\\}"
    escaped_pwd="${escaped_pwd//\"/\\\"}"
    
    local js
    js=$(cat <<EOF
db = db.getSiblingDB("${db}");
const user = "${user}";
const pwd = "${escaped_pwd}";
try {
  const existing = db.getUser(user);
  if (existing) {
    print('ERROR: User already exists: ' + user);
  } else {
    db.createUser({ user: user, pwd: pwd, roles: [{ role: 'readWrite', db: "${db}" }] });
    print('Created user: ' + user);
  }
} catch(e) {
  if (e.message && e.message.includes('User') && e.message.includes('not found')) {
    db.createUser({ user: user, pwd: pwd, roles: [{ role: 'readWrite', db: "${db}" }] });
    print('Created user: ' + user);
  } else {
    print('ERROR: ' + e.message);
  }
}
EOF
)

    local result
    if [[ "$MONGO_AUTH_ENABLED" == "yes" ]]; then
        result=$("$MONGO_SHELL" --quiet \
            --username "$MONGO_ADMIN_USER" \
            --password "$MONGO_ADMIN_PASS" \
            --authenticationDatabase "$MONGO_AUTH_DB" \
            --eval "${js}" 2>&1)
    else
        result=$("$MONGO_SHELL" --quiet --eval "${js}" 2>&1)
    fi
    
    echo "$result"
    
    # Return success if user was created
    if echo "$result" | grep -q "Created user:"; then
        return 0
    else
        return 1
    fi
}

for attempt in 1 2 3 4 5; do
    suffix="$("$PYTHON_BIN" - <<'PY'
import secrets
print(secrets.token_hex(4))
PY
)"
    APP_DB_USER="netlens_app_${suffix}"
    echo "Attempting to create MongoDB user '${APP_DB_USER}' in database '${APP_DB}'..."
    create_result=$(create_mongo_user "$APP_DB_USER" "$APP_DB_PASS" 2>&1)
    echo "Result: $create_result"
    
    if echo "$create_result" | grep -q "Created user:"; then
        echo "✅ Created MongoDB user: ${APP_DB_USER}"
        break
    elif echo "$create_result" | grep -q "User already exists"; then
        echo "⚠️  User already exists, trying different username..."
    elif echo "$create_result" | grep -q "Authentication failed\|not authorized"; then
        echo "ERROR: MongoDB authentication/authorization failed." >&2
        echo "The provided admin credentials don't have permission to create users." >&2
        echo "Please ensure the admin user has 'userAdmin' or 'userAdminAnyDatabase' role." >&2
        echo "" >&2
        echo "To grant privileges, you can either:" >&2
        echo "  1. Run: ./scripts/grant-mongo-privileges.sh" >&2
        echo "  2. Manually run:" >&2
        echo "     mongosh -u <superuser> --authenticationDatabase admin" >&2
        echo "     use admin" >&2
        echo "     db.grantRolesToUser('${MONGO_ADMIN_USER}', [{ role: 'userAdminAnyDatabase', db: 'admin' }])" >&2
        echo "" >&2
        echo "Full error: $create_result" >&2
        exit 1
    else
        echo "Failed (attempt ${attempt}/5)."
        echo "Error details: $create_result"
        if [[ "$attempt" -lt 5 ]]; then
            echo "Retrying with a different username..."
        fi
    fi
    
    if [[ "$attempt" -eq 5 ]]; then
        echo "ERROR: Failed to create MongoDB application user after 5 attempts." >&2
        echo "Last error: $create_result" >&2
        echo "" >&2
        echo "Common issues:" >&2
        echo "  1. User lacks privileges - run: ./scripts/grant-mongo-privileges.sh" >&2
        echo "  2. MongoDB not running - check: systemctl status mongod" >&2
        echo "  3. Network issues - verify MongoDB is accessible" >&2
        exit 1
    fi
done
    MONGO_USER_CREATED="yes"
fi

# Generate application admin credentials
APP_SESSION_SECRET="$("$PYTHON_BIN" - <<'PY'
import secrets
print(secrets.token_hex(48))
PY
)"

DEFAULT_ADMIN_USERNAME="admin"
DEFAULT_ADMIN_PASSWORD="$(generate_urlsafe_password)"

echo ""
echo "Generated credentials (will be saved to summary.txt):"
echo "  NetLens admin username: ${DEFAULT_ADMIN_USERNAME}"
echo "  NetLens admin password: ${DEFAULT_ADMIN_PASSWORD}"
if [[ "$MONGO_USER_CREATED" == "yes" ]]; then
    echo "  MongoDB app user: ${APP_DB_USER}"
    echo "  MongoDB app password: ${APP_DB_PASS}"
fi
echo ""
echo "⚠️  IMPORTANT: Save these credentials from summary.txt before deleting it!"
echo ""

# Update config.env with MongoDB credentials
echo "Writing /opt/netlens/config.env ..."

# Build appropriate MONGO_URI based on whether we created a user
if [[ "$MONGO_USER_CREATED" == "yes" ]]; then
    MONGO_URI_VALUE="mongodb://${APP_DB_USER}:${APP_DB_PASS}@localhost:${MONGO_PORT}/${APP_DB}?authSource=${APP_DB}"
else
    # No auth or manual setup
    MONGO_URI_VALUE="mongodb://localhost:${MONGO_PORT}/${APP_DB}"
fi

cat > /opt/netlens/config.env << EOF
# MongoDB Configuration
MONGO_URI=${MONGO_URI_VALUE}
MONGO_DB_NAME=${APP_DB}

# Application Authentication
DEFAULT_ADMIN_USERNAME=${DEFAULT_ADMIN_USERNAME}
DEFAULT_ADMIN_PASSWORD=${DEFAULT_ADMIN_PASSWORD}
APP_SESSION_SECRET=${APP_SESSION_SECRET}
BCRYPT_ROUNDS=12

# Session cookie behavior
# auto: sets secure cookies on HTTPS requests, non-secure on HTTP requests (useful with CRA dev proxy)
COOKIE_SECURE=auto

# CORS (Frontend URL)
CORS_ORIGIN=http://localhost:${CORS_PORT}

# Network Settings (UPDATE THESE FOR YOUR NETWORK)
NETWORK_RANGES=192.168.1.0/24
# Disable scheduled scans by default (run only when triggered from UI/API)
SCAN_SCHEDULE=disabled

# API Settings
PORT=${HTTP_PORT}
ENABLE_HTTPS=${ENABLE_HTTPS}
HTTPS_PORT=${HTTPS_PORT}
TLS_CERT_PATH=${TLS_CERT_PATH}
TLS_KEY_PATH=${TLS_KEY_PATH}
NODE_ENV=production

# Logging
LOG_FILE=/opt/netlens/logs/scanner.log
LOG_LEVEL=INFO
EOF

# Verify MongoDB connectivity
if [[ "$MONGO_USER_CREATED" == "yes" ]]; then
    echo "Verifying MongoDB connectivity with application credentials..."
    export MONGO_URI="${MONGO_URI_VALUE}"
    export MONGO_DB_NAME="$APP_DB"
    "$PYTHON_BIN" - <<'PY'
import os
from pymongo import MongoClient

uri = os.environ.get('MONGO_URI')
db_name = os.environ.get('MONGO_DB_NAME', 'netlens')
try:
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    client[db_name].command('ping')
    print('✅ MongoDB connection verified')
except Exception as e:
    print(f'⚠️  MongoDB connection test failed: {e}')
    print('   The service may fail to start. Check MongoDB status and credentials.')
PY
else
    echo "⚠️  Skipping MongoDB connection test (user creation was skipped)"
    echo "   Make sure MongoDB is accessible at: ${MONGO_URI_VALUE}"
fi

# Install systemd services
echo "Installing systemd services..."
cp /opt/netlens/netlens.service /etc/systemd/system/
cp /opt/netlens/netlensscan.service /etc/systemd/system/

# Reload systemd
systemctl daemon-reload

# If upgrading from older installs, stop/disable legacy unit names.
systemctl stop api.service 2>/dev/null || true
systemctl disable api.service 2>/dev/null || true
systemctl stop netLens.service 2>/dev/null || true
systemctl disable netLens.service 2>/dev/null || true

echo "Systemd units installed: netlensscan.service (API), netlens.service (scanner)"

ENABLE_NOW="no"
if prompt_yes_no "Enable and start NetLens services now?" "y"; then
        ENABLE_NOW="yes"

        echo "Enabling + starting API service (netlensscan.service)..."
        systemctl enable netlensscan.service
        systemctl start netlensscan.service

        # Scanner service is optional (scans are usually orchestrated by the API server)
        if prompt_yes_no "Enable and start scanner service (netlens.service)?" "n"; then
                echo "Enabling + starting scanner service (netlens.service)..."
                systemctl enable netlens.service
                systemctl start netlens.service
        else
                systemctl disable netlens.service 2>/dev/null || true
                systemctl stop netlens.service 2>/dev/null || true
        fi
else
        echo "Skipping enable/start. You can enable later with systemctl (see summary.txt)."
fi

SUMMARY_FILE="/opt/netlens/summary.txt"
echo "Writing install summary to ${SUMMARY_FILE} ..."

# Build summary content conditionally
MONGO_ADMIN_SUMMARY=""
if [[ "$MONGO_ADMIN_CREATED" == "yes" ]]; then
    MONGO_ADMIN_SUMMARY="
MongoDB Admin (CREATED by installer):
- Admin username: ${MONGO_ADMIN_USER}  (auto-generated)
- Admin password: ${MONGO_ADMIN_PASS}  (auto-generated)
- Auth database: ${MONGO_AUTH_DB}
- Roles: userAdminAnyDatabase, dbAdminAnyDatabase
- Login: mongosh --username ${MONGO_ADMIN_USER} --password '${MONGO_ADMIN_PASS}' --authenticationDatabase ${MONGO_AUTH_DB}
"
fi

MONGO_SUMMARY=""
if [[ "$MONGO_USER_CREATED" == "yes" ]]; then
    MONGO_SUMMARY="
MongoDB Application User:
- Database: ${APP_DB}
- Port: ${MONGO_PORT}
- App DB user: ${APP_DB_USER}  (auto-generated)
- App DB pass: ${APP_DB_PASS}  (auto-generated)
- MONGO_URI: ${MONGO_URI_VALUE}
- Login test: mongosh \"${MONGO_URI_VALUE}\" --eval \"db.runCommand({ ping: 1 })\""
else
    MONGO_SUMMARY="
MongoDB:
- Database: ${APP_DB}
- Port: ${MONGO_PORT}
- MONGO_URI: ${MONGO_URI_VALUE}
- ⚠️  MongoDB user was NOT created automatically
- You may need to create a user manually if MongoDB has auth enabled"
fi

cat > "${SUMMARY_FILE}" <<EOF
NetLens Install Summary
Generated: $(date -Is)

⚠️  IMPORTANT: This file contains secrets (passwords). 
    Store them securely and DELETE this file after copying the information.
    Suggested: sudo shred -u ${SUMMARY_FILE}

================================================================================
CREDENTIALS (Auto-Generated)
================================================================================

NetLens Web Admin:
- Username: ${DEFAULT_ADMIN_USERNAME}
- Password: ${DEFAULT_ADMIN_PASSWORD}

${MONGO_SUMMARY}

================================================================================
INSTALLATION DETAILS
================================================================================

Install location:
- /opt/netlens

API:
- HTTP:  http://localhost:${HTTP_PORT}
- Health: curl http://localhost:${HTTP_PORT}/health
- HTTPS enabled: ${ENABLE_HTTPS}
- HTTPS port: ${HTTPS_PORT}
- TLS cert: ${TLS_CERT_PATH}
- TLS key:  ${TLS_KEY_PATH}

Frontend / CORS:
- CORS_ORIGIN=http://localhost:${CORS_PORT}

Systemd services:
- netlensscan.service (API)
- netlens.service (scanner)

If you chose NOT to enable/start services during install:
- Enable + start API now:
    sudo systemctl enable --now netlensscan.service
- (Optional) Enable + start scanner now:
    sudo systemctl enable --now netlens.service

Stop / Start / Disable:
- Start:   sudo systemctl start netlensscan.service
- Stop:    sudo systemctl stop netlensscan.service
- Restart: sudo systemctl restart netlensscan.service
- Status:  sudo systemctl status netlensscan.service --no-pager
- Disable autostart: sudo systemctl disable netlensscan.service

Scanner service (optional):
- Start:   sudo systemctl start netlens.service
- Stop:    sudo systemctl stop netlens.service
- Status:  sudo systemctl status netlens.service --no-pager

Logs:
- API logs:     sudo journalctl -u netlensscan.service -n 200 --no-pager
- Scanner logs: sudo journalctl -u netlens.service -n 200 --no-pager

Helper scripts:
- Manager UI: sudo /opt/netlens/scripts/netlens-manager.sh
- Stop all:   sudo /opt/netlens/scripts/netlens-stop.sh

EOF

chmod 600 "${SUMMARY_FILE}"

echo ""
echo "====================================="
echo "Installation Complete!"
echo "====================================="
echo ""
echo "Services Status:"
if [[ "$ENABLE_NOW" == "yes" ]]; then
    systemctl status netlensscan.service --no-pager || true
else
    echo "(Not started during install)"
    systemctl status netlensscan.service --no-pager || true
fi
echo ""
echo "Scanner service (netlens.service): optional (enable/start if desired)"
echo ""
echo "Configuration file: /opt/netlens/config.env"
echo "Install summary (contains secrets): ${SUMMARY_FILE}"
echo "Logs: /opt/netlens/logs/"
echo ""
echo "API Server: http://localhost:${HTTP_PORT}"
echo "Health Check: curl http://localhost:${HTTP_PORT}/health"
echo "Manager UI: sudo /opt/netlens/scripts/netlens-manager.sh"
echo ""
echo "Next Steps:"
echo "1. Edit /opt/netlens/config.env with your network ranges"
echo "2. (Optional) Build frontend: see frontend/README.md"
echo ""
echo "Required external programs (besides Python) used by NetLens:" 
echo "- MongoDB server + shell (mongod + mongosh/mongo)"
echo "- nmap (host + service discovery)"
echo "- tcpdump (packet capture helpers)"
echo "- Node.js + npm (REST API server)"
echo ""
