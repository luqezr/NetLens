# MongoDB Installation Troubleshooting Guide

## Authentication Failed During Install

If you see `Authentication failed` when running `install.sh`, it means the MongoDB credentials you provided don't have permission to create users.

### Solution 1: Use the Helper Script

```bash
./scripts/grant-mongo-privileges.sh
```

This will prompt you for:
1. A MongoDB superuser (e.g., `root` or `admin`) with existing privileges
2. The username you want to grant privileges to
3. It will then grant the necessary roles

### Solution 2: Manual Privilege Grant

Connect to MongoDB with a superuser account and run:

```javascript
use admin
db.grantRolesToUser('YOUR_USERNAME', [
    { role: 'userAdminAnyDatabase', db: 'admin' },
    { role: 'dbAdminAnyDatabase', db: 'admin' }
])
```

### Solution 3: Create a New Admin User

If you don't remember your MongoDB root password, you can:

1. Stop MongoDB authentication temporarily
2. Edit `/etc/mongod.conf` and comment out the `security:` section
3. Restart MongoDB: `sudo systemctl restart mongod`
4. Connect without auth: `mongosh`
5. Create a new admin user:

```javascript
use admin
db.createUser({
  user: "netlensAdmin",
  pwd: "YOUR_SECURE_PASSWORD",
  roles: [
    { role: "userAdminAnyDatabase", db: "admin" },
    { role: "dbAdminAnyDatabase", db: "admin" },
    { role: "readWriteAnyDatabase", db: "admin" }
  ]
})
```

6. Re-enable authentication in `/etc/mongod.conf`
7. Restart MongoDB: `sudo systemctl restart mongod`
8. Re-run the NetLens installer with the new credentials

## Checking User Roles

To see what roles a user has:

```bash
mongosh -u YOUR_USERNAME --authenticationDatabase admin
```

Then run:

```javascript
use admin
db.getUser('YOUR_USERNAME')
```

Look for these roles in the output:
- `userAdminAnyDatabase` - Can create users in any database
- `dbAdminAnyDatabase` - Can manage any database
- `root` - Full superuser access

## Common Error Messages

### "Authentication failed"
- **Cause**: Wrong username, password, or authentication database
- **Solution**: Double-check credentials, try `admin` as auth database

### "not authorized on admin to execute command"
- **Cause**: User doesn't have the required roles
- **Solution**: Grant `userAdminAnyDatabase` role (see above)

### "connection refused"
- **Cause**: MongoDB isn't running
- **Solution**: `sudo systemctl start mongod`

### "connection timeout"
- **Cause**: MongoDB is running but not accepting connections
- **Solution**: Check `/etc/mongod.conf` - ensure `bindIp` allows connections

## MongoDB Status Check

Check if MongoDB is running:
```bash
sudo systemctl status mongod
```

Check MongoDB logs:
```bash
sudo journalctl -u mongod -n 50 --no-pager
```

Test connection:
```bash
mongosh --eval "db.runCommand({ connectionStatus: 1 })"
```

Test with authentication:
```bash
mongosh -u USERNAME -p PASSWORD --authenticationDatabase admin --eval "db.runCommand({ connectionStatus: 1 })"
```
