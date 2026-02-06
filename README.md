# NetLens - Network Discovery Platform

A comprehensive network scanning and monitoring solution that continuously discovers, identifies, and tracks all devices on your network.

## Features

- **Device inventory**: IP, MAC (when available), vendor, OS guess, services/ports, and last-seen tracking
- **Vulnerability surfacing (best-effort)**: Extracts CVEs from Nmap NSE script output and shows them in the UI (Vulnerabilities column + CVE list)
- **Scheduling**: Interval scans, exact one-shot scans, and recurring **daily/weekly** schedules
- **Scan history + live log**: View recent scans, per-scan device snapshots, and a streaming live log
- **Identity over time**: Tracks IP changes for a device (keeps `previous_ips` when MAC identity stays stable)
- **Topology + alerts**: Visual network graph plus alerts for notable events
- **REST API**: Device, scan, stats, alerts, and topology endpoints for integrations

## 🛠️ Technology Stack

### Backend
- **Python 3**: Network scanning (nmap, scapy)
- **Node.js + Express**: REST API server
- **MongoDB**: Database storage

### Frontend (Recommended)
- **React**: Modern UI framework
- **React Flow / D3.js**: Network topology visualization
- **Material-UI / Ant Design**: UI components
- **Recharts**: Dashboard charts

## 📋 Prerequisites

- Linux (Debian/Ubuntu-based or Arch Linux-based)
- Root/sudo access (required for network scanning)

NetLens uses these external programs (the installer installs most of them):
- MongoDB server + shell (mongod + mongosh/mongo)
- Python 3.8+
- Node.js 16+
- npm
- nmap
- tcpdump
- OpenSSL (optional, for generating HTTPS certificate)

## 🚀 Quick Installation (Debian or Arch)

```bash
# Clone repository
git clone <your-repo>
cd NetLens

# Run installation script (as root)
sudo ./install.sh

# Edit configuration
sudo nano /opt/netlens/config.env
# Update NETWORK_RANGES with your network subnets

# Restart services
sudo systemctl restart netlensscan.service
```

Notes:

- The installer deploys to `/opt/netlens`.
- The API service is `netlensscan.service`.
- The scanner service is `netlens.service` (runs as root for better OS/MAC discovery).
- The production React frontend is built during install and served by the API on the same port (default `http://localhost:5000/`).

## 🔄 Updating NetLens (update.sh)

NetLens includes an in-place updater script, designed for the common workflow:

1) Download a newer NetLens repo copy (or `git pull`)
2) Run the updater
3) Keep your existing database/users/config/logs

From the NetLens repo folder:

```bash
sudo ./update.sh
```

If the repo folder is a git checkout and you want the script to pull the newest commit first:

```bash
sudo ./update.sh --pull
```

What `update.sh` does:

- Stops `netlensscan.service` and `netlens.service`
- Syncs new application files into `/opt/netlens`
- Preserves local state:
   - `/opt/netlens/config.env`
   - `/opt/netlens/logs/`
   - `/opt/netlens/venv/`
   - `/opt/netlens/certs/` (TLS material)
- Reinstalls dependencies and rebuilds the React frontend
- Restarts services

Safety behavior:

- If the frontend build fails, it restores the previous `frontend/build` so the UI doesn’t go blank.

To run the API manually for development:
- Stop the service: `sudo systemctl stop netlensscan.service`
- Or use a different port: `PORT=5001 npm start`

To run the frontend in dev mode:
```bash
cd frontend
npm start
```

During install you will be prompted for:
- Distro family (Debian/Ubuntu vs Arch)
- Whether MongoDB authentication is enabled (and admin credentials if needed)
- Ports for HTTP/HTTPS and MongoDB (defaults provided)
- Whether to generate a self-signed OpenSSL certificate for HTTPS

Scanner behavior:
- Scans are typically triggered by the API (UI “Run Scan Now” or schedule settings), via a MongoDB queue (`scan_requests`).
- `netlens.service` can also pick up queued scan requests and run with elevated privileges.
- Important: avoid running multiple scan workers simultaneously unless you intentionally want parallel scan execution.

Stop everything:
```bash
sudo ./scripts/netlens-stop.sh
# also disable autostart
sudo ./scripts/netlens-stop.sh --disable
```

Manage services with a console UI (health + start/stop + logs):
```bash
sudo ./scripts/netlens-manager.sh
```

## 📁 Project Structure

```
NetLens/
├── scanner_service.py      # Python scanning service
├── database/
│   └── mongo_manager.py    # MongoDB operations
├── server.js               # Node.js API server
├── routes/
│   ├── devices.js          # Device API endpoints
│   ├── stats.js            # Statistics endpoints
│   ├── topology.js         # Network topology endpoints
│   └── alerts.js           # Alert management endpoints
├── models/
│   └── Device.js           # Device data model
├── frontend/               # React frontend (CRA)
├── config.env              # Configuration file
├── requirements.txt        # Python dependencies
├── package.json            # Node.js dependencies
└── install.sh              # Installation script
```

## ⚙️ Configuration

Edit `/opt/netlens/config.env`:

```env
# MongoDB Configuration
MONGO_URI=mongodb://netlens_app_user:password@localhost:27017/netlens
MONGO_DB_NAME=netlens

# Network Settings - Update with your network ranges
NETWORK_RANGES=192.168.1.0/24,10.0.0.0/24

# Scheduled scans (legacy scanner-only mode)
# The UI scheduler is configured via the web UI and stored in MongoDB.
# SCAN_SCHEDULE is still supported by the standalone scanner service as:
#   - disabled/off
#   - integer minutes (e.g. 60)
#   - 5-field cron (m h dom mon dow)
SCAN_SCHEDULE=disabled

# Nmap scan tuning
# By default, NetLens adds "--script vuln" to per-host scans (unless you fully override args).
# You can change or disable this:
#   SCAN_NMAP_SCRIPTS=vuln            # (default)
#   SCAN_NMAP_SCRIPTS="vuln or safe" # safer but still informative
#   SCAN_NMAP_SCRIPTS=off             # don't add --script automatically
# You can also fully override nmap arguments:
#   SCAN_NMAP_ARGS=-sS -A --top-ports 1000 -T4 -Pn
# and optionally cap NSE runtime:
#   SCAN_SCRIPT_TIMEOUT=120s

# Additional scan knobs (optional)
# SCAN_TOP_PORTS=1000
# SCAN_HOST_TIMEOUT=120s
# SCAN_MAX_RETRIES=2
# SCAN_ASSUME_UP=1

# API Settings
PORT=5000
NODE_ENV=production
```

### Vulnerability & CVE detection

When NSE scripts are enabled (default: `SCAN_NMAP_SCRIPTS=vuln`), the scanner parses script output and extracts CVE identifiers.
They’re stored on each device record under:

- `security.cves` (array of CVE strings)
- `security.cve_count` (integer)

Notes:

- Running vulnerability scripts can be slower and may trigger IDS/IPS alerts.
- If you see timeouts, set `SCAN_SCRIPT_TIMEOUT` to a higher value or disable scripts with `SCAN_NMAP_SCRIPTS=off`.

UI behavior:

- Devices table includes a **Vulnerabilities** indicator (✅ when none recorded, ❌ when CVEs exist).
- Device details show the detected CVE list (clickable links to NVD).

### Scheduled scans

The UI supports these schedule modes:

- **Interval**: run a scan every N minutes.
- **Exact date/time (one-shot)**: choose a calendar date and time.
- **Daily**: run at a specific local time every day.
- **Weekly**: run on selected weekdays at a specific local time.

The “Next 10 occurrences” list is computed from the actual next scheduled run time (so it doesn’t drift as the page refreshes).

## 🔌 API Endpoints

### Devices
- `GET /api/devices` - List all devices
- `GET /api/devices/:ip` - Get specific device
- `PATCH /api/devices/:ip` - Update device metadata
- `DELETE /api/devices/:ip` - Delete device

### Statistics
- `GET /api/stats` - Dashboard statistics

### Topology
- `GET /api/topology` - Network topology data

### Alerts
- `GET /api/alerts` - List alerts
- `POST /api/alerts/:id/acknowledge` - Acknowledge alert

### Health
- `GET /health` - Service health check

## 🎨 Frontend

NetLens ships with a React frontend in `frontend/`.

- Production installs: the installer builds the frontend and the API serves it from `/`.
- Development: run `npm start` in `frontend/` and point `CORS_ORIGIN` at the dev server if needed.

## 📊 Dashboard Features

The web UI includes:

1. **Overview Dashboard**
   - Total devices (online/offline)
   - Device types breakdown
   - Recent alerts
   - Network health score

2. **Device List**
   - Searchable/filterable table
   - Device details: IP, MAC, hostname, vendor, OS
   - Connection type estimate (wired/wireless/unknown)
   - Last seen timestamp
   - Vulnerabilities indicator + CVE details (when available)

3. **Network Topology**
   - Interactive network graph
   - Device relationships
   - Connection types visualization
   - Zoom/pan controls

4. **Alerts**
   - New device notifications
   - Offline device alerts
   - Security concerns
   - Acknowledge/dismiss functionality

## 🔒 Security Considerations

1. **Application login**: NetLens uses session-based authentication.
   - Default username: `admin (proposed by ./install, can be replaced there)` 
   - Default password: `automatically generated during ./install`
   - Change it immediately after first login via the profile menu in the UI.
2. **Firewall**: Restrict API access to trusted networks
3. **MongoDB**: Use authentication and restrict bind addresses in production
4. **HTTPS**: Use the installer-generated cert for testing, or a real cert in production
5. **Permissions**: Scanner runs as root (raw sockets), API runs as limited user

## 🔐 Strongly Recommended: Enable MongoDB Authentication

Running MongoDB without authentication is convenient for local testing, but it is not recommended for real deployments.
For better safety, enable MongoDB auth and restrict network exposure.

### Step 1: Create an admin user (if you don’t already have one)

If MongoDB auth is currently disabled, you can still create users.

```bash
mongosh
use admin
db.createUser({
   user: "myMongoDBAdmin",
   pwd: "<STRONG_PASSWORD>",
   roles: [
      { role: "userAdminAnyDatabase", db: "admin" },
      { role: "dbAdminAnyDatabase", db: "admin" }
   ]
})
```

Installer note:

- If you answered **No** to “Does MongoDB require authentication?”, the installer will now optionally generate this admin user for you with a random password and store it in `/opt/netlens/summary.txt`.

### Step 2: Enable authorization in MongoDB

Edit your MongoDB config (commonly `/etc/mongod.conf`) and enable authorization:

```yaml
security:
   authorization: enabled
```

Then restart MongoDB:

```bash
sudo systemctl restart mongod || sudo systemctl restart mongodb
```

### Step 3: Create (or keep) the NetLens application user

NetLens uses a dedicated user for the `netlens` database. Create one (or reuse the one from `summary.txt`):

```bash
mongosh --username myMongoDBAdmin --password '<ADMIN_PASSWORD>' --authenticationDatabase admin
use netlens
db.createUser({
   user: "netlens_app_user",
   pwd: "<APP_PASSWORD>",
   roles: [{ role: "readWrite", db: "netlens" }]
})
```

### Step 4: Update NetLens config.env

Update `/opt/netlens/config.env`:

```env
MONGO_URI=mongodb://netlens_app_user:<APP_PASSWORD>@localhost:27017/netlens
```

Then restart the API:

```bash
sudo systemctl restart netlensscan.service
```

### Extra hardening tips

- Bind MongoDB to localhost only unless you explicitly need remote access (`bindIp: 127.0.0.1`).
- Use a firewall to prevent untrusted network access to port 27017.

## 🔧 Troubleshooting

### MAC address and vendor are missing

MAC addresses are only available when the scanner can observe L2 neighbor information (same broadcast domain / ARP visibility). Common reasons you won’t get MAC/vendor:

- Target is on a different VLAN/subnet behind routing
- ARP is blocked/filtered
- Scan runs without enough privileges (ARP/raw-socket limitations)

NetLens does a best-effort MAC vendor lookup using Nmap’s OUI database when a MAC is available.

### Scan crashes with DuplicateKeyError on mac_address

If you see `E11000 duplicate key error ... mac_address: null`, your DB has a MAC unique index that is indexing `null` values.
Run the repair script once:

```bash
sudo /opt/netlens/venv/bin/python /opt/netlens/scripts/fix_database.py
```

### Scanner log Permission denied

If you see `PermissionError: ... /opt/netlens/logs/scanner.log`, either:

- Fix permissions:
   ```bash
   sudo chown -R netlens:netlens /opt/netlens/logs
   ```
- Or rely on the built-in fallback (scanner will log to a writable location, e.g. `/tmp/...`).

### Check service status
```bash
sudo systemctl status netlens.service
sudo systemctl status netlensscan.service
```

### View logs
```bash
sudo tail -f /opt/netlens/logs/scanner.log
sudo journalctl -u netlensscan -f
sudo journalctl -u netlens -f
```

### Test API
```bash
curl http://localhost:5000/health
curl http://localhost:5000/api/devices

```

### Manual scan
```bash
sudo /opt/netlens/venv/bin/python /opt/netlens/scanner_service.py --run-once
```

## 📈 Performance

- Scan duration depends on host count, enabled NSE scripts, and port selection.
- Low CPU usage between scans; scanning is the dominant workload.
- MongoDB indexes keep device/scan queries fast.
- Scheduling is configurable (interval, exact one-shot, daily, weekly).

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

## 📄 License

MIT License

## 🙏 Credits

Inspired by professional network monitoring and industrial security solutions.
