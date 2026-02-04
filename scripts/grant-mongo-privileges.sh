#!/bin/bash
# Helper script to grant MongoDB user creation privileges
# Run this if the installer says your user doesn't have permission to create users

set -euo pipefail

echo "MongoDB Privilege Helper"
echo "========================"
echo ""
echo "This script will grant user creation privileges to a MongoDB user."
echo "You need to authenticate with a user that already has these privileges"
echo "(such as the root user created during MongoDB installation)."
echo ""

read -r -p "Enter MongoDB superuser username (e.g., root, admin): " SUPER_USER
read -r -s -p "Enter superuser password: " SUPER_PASS
echo ""
read -r -p "Enter authentication database [admin]: " AUTH_DB
AUTH_DB="${AUTH_DB:-admin}"

read -r -p "Enter the username to grant privileges to: " TARGET_USER

echo ""
echo "Granting userAdminAnyDatabase role to: $TARGET_USER"
echo ""

MONGO_SHELL="mongosh"
if ! command -v mongosh >/dev/null 2>&1; then
    MONGO_SHELL="mongo"
fi

$MONGO_SHELL --quiet \
    --username "$SUPER_USER" \
    --password "$SUPER_PASS" \
    --authenticationDatabase "$AUTH_DB" \
    --eval "
db = db.getSiblingDB('admin');
db.grantRolesToUser('${TARGET_USER}', [
    { role: 'userAdminAnyDatabase', db: 'admin' },
    { role: 'dbAdminAnyDatabase', db: 'admin' }
]);
print('✅ Granted privileges to user: ${TARGET_USER}');
print('   Roles: userAdminAnyDatabase, dbAdminAnyDatabase');
print('');
print('You can now re-run the NetLens installer.');
"

echo ""
echo "Done!"
