#!/bin/bash

# NetLens Uninstallation Script
# Removes NetLens installation, services, and optionally drops the MongoDB database

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

echo "====================================="
echo "NetLens Uninstallation"
echo "====================================="
echo ""
echo "WARNING: This will remove NetLens completely from your system."
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo ./uninstall.sh)"
    exit 1
fi

if ! prompt_yes_no "Continue with uninstallation?" "n"; then
    echo "Uninstallation cancelled."
    exit 0
fi

echo ""
echo "Stopping and disabling NetLens services..."
systemctl stop netlensscan.service 2>/dev/null || true
systemctl stop netlens.service 2>/dev/null || true
systemctl disable netlensscan.service 2>/dev/null || true
systemctl disable netlens.service 2>/dev/null || true

echo "Removing systemd service files..."
rm -f /etc/systemd/system/netlensscan.service
rm -f /etc/systemd/system/netlens.service
systemctl daemon-reload

echo "Killing any remaining NetLens processes..."
pkill -f "/opt/netlens/server.js" 2>/dev/null || true
pkill -f "/opt/netlens/scanner_service.py" 2>/dev/null || true
sleep 2

# MongoDB database cleanup
if prompt_yes_no "Drop the NetLens MongoDB database?" "y"; then
    MONGO_SHELL=""
    if ! MONGO_SHELL=$(detect_mongo_shell); then
        echo "WARNING: MongoDB shell (mongosh/mongo) not found. Skipping database cleanup."
    else
        echo ""
        MONGO_AUTH_ENABLED="no"
        if prompt_yes_no "Is MongoDB authentication enabled?" "n"; then
            MONGO_AUTH_ENABLED="yes"
            read -r -p "MongoDB admin username: " MONGO_ADMIN_USER
            read -r -s -p "MongoDB admin password: " MONGO_ADMIN_PASS
            echo ""
            read -r -p "MongoDB authentication database [admin]: " MONGO_AUTH_DB
            MONGO_AUTH_DB="${MONGO_AUTH_DB:-admin}"
        fi

        DB_NAME="netlens"
        read -r -p "NetLens database name [${DB_NAME}]: " DB_INPUT
        DB_NAME="${DB_INPUT:-$DB_NAME}"

        echo "Dropping MongoDB database '${DB_NAME}'..."
        
        if [[ "$MONGO_AUTH_ENABLED" == "yes" ]]; then
            "$MONGO_SHELL" --quiet \
                --username "$MONGO_ADMIN_USER" \
                --password "$MONGO_ADMIN_PASS" \
                --authenticationDatabase "$MONGO_AUTH_DB" \
                --eval "db.getSiblingDB('${DB_NAME}').dropDatabase(); print('Database ${DB_NAME} dropped');" || echo "Failed to drop database (may not exist)"
        else
            "$MONGO_SHELL" --quiet \
                --eval "db.getSiblingDB('${DB_NAME}').dropDatabase(); print('Database ${DB_NAME} dropped');" || echo "Failed to drop database (may not exist)"
        fi
    fi
fi

echo ""
echo "Removing NetLens installation directory..."
if [ -d "/opt/netlens" ]; then
    rm -rf /opt/netlens
    echo "✓ /opt/netlens removed"
fi

echo ""
echo "Removing NetLens system user..."
if id -u netlens >/dev/null 2>&1; then
    userdel netlens 2>/dev/null || true
    echo "✓ User 'netlens' removed"
fi

# Clean up session cookies
rm -f /tmp/netlens-manager-cookies.txt 2>/dev/null || true

echo ""
echo "====================================="
echo "Uninstallation Complete!"
echo "====================================="
echo ""
echo "NetLens has been removed from your system."
echo ""
echo "Items NOT removed (manual cleanup if desired):"
echo "  - MongoDB server (mongod service)"
echo "  - System packages (Node.js, Python, nmap, etc.)"
echo "  - MongoDB users (if you want to clean them up manually)"
echo ""
echo "To completely remove MongoDB:"
echo "  sudo systemctl stop mongod"
echo "  sudo apt remove mongodb-org  # or: sudo pacman -R mongodb"
echo ""
