# NetLens - Network Discovery Platform

A comprehensive network scanning and monitoring solution that continuously discovers, identifies, and tracks all devices on your network.

## 🌟 Features

- **Automated Network Discovery**: Scans network every hour to discover all connected devices
- **Device Identification**: Identifies device type, OS, vendor, and running services
- **Connection Detection**: Detects wired vs wireless connections
- **Real-time Dashboard**: Web-based interface showing network topology and device stats
- **Alert System**: Notifications for new devices, offline devices, and security concerns
- **Network Topology Visualization**: Visual representation of network connections
- **RESTful API**: Complete API for integration with other systems

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
sudo nano /opt/netscanner/config.env
# Update NETWORK_RANGES with your network subnets

# Restart services
sudo systemctl restart netlensscan.service netlens.service
```

Note: the installer installs the systemd units `netlensscan.service` (API) and `netlens.service` (scanner).
During install, you can choose whether to enable/start them immediately.
If you run `npm start` in this repo after installing, you will likely see `EADDRINUSE` because the service is already listening.

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
- Scans are triggered by the API server (via the UI or schedule settings).
- The installer does **not** start `netlens.service` by default.

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
Network Collector/
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
├── frontend/               # React frontend (to be created)
├── config.env              # Configuration file
├── requirements.txt        # Python dependencies
├── package.json            # Node.js dependencies
└── install.sh              # Installation script
```

## ⚙️ Configuration

Edit `/opt/netscanner/config.env`:

```env
# MongoDB Configuration
MONGO_URI=mongodb://netlens_app_user:password@localhost:27017/netlens
MONGO_DB_NAME=netlens

# Network Settings - Update with your network ranges
NETWORK_RANGES=192.168.1.0/24,10.0.0.0/24
SCAN_SCHEDULE=*/60 * * * *  # Every hour

# API Settings
PORT=5000
NODE_ENV=production
```

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

## 🎨 Frontend Setup (Next Step)

For the best experience, I recommend:

### Option 1: React + Material-UI + React Flow (Recommended)
```bash
cd /opt/netscanner
npx create-react-app frontend
cd frontend
npm install @mui/material @emotion/react @emotion/styled
npm install reactflow
npm install recharts axios
```

### Option 2: Next.js (For production-ready app)
```bash
cd /opt/netscanner
npx create-next-app@latest frontend
cd frontend
npm install @mui/material reactflow recharts axios
```

### Option 3: Vue.js + Element Plus
```bash
cd /opt/netscanner
npm create vue@latest frontend
cd frontend
npm install element-plus vue-flow-form echarts
```

## 📊 Dashboard Features

The frontend will display:

1. **Overview Dashboard**
   - Total devices (online/offline)
   - Device types breakdown
   - Recent alerts
   - Network health score

2. **Device List**
   - Searchable/filterable table
   - Device details: IP, MAC, hostname, vendor, OS
   - Connection type (wired/wireless)
   - Last seen timestamp

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
   - Default username: `sudo`
   - Default password: `Sudo123`
   - Change it immediately after first login via the profile menu in the UI.
2. **Firewall**: Restrict API access to trusted networks
3. **MongoDB**: Use authentication and restrict bind addresses in production
4. **HTTPS**: Use the installer-generated cert for testing, or a real cert in production
5. **Permissions**: Scanner runs as root (raw sockets), API runs as limited user

## 🔧 Troubleshooting

### Check service status
```bash
sudo systemctl status netlens.service
sudo systemctl status netlensscan.service
```

### View logs
```bash
sudo tail -f /opt/netscanner/logs/scanner.log
sudo journalctl -u netscanner -f
sudo journalctl -u api -f
```

### Test API
```bash
curl http://localhost:5000/health
curl http://localhost:5000/api/devices
```

### Manual scan
```bash
sudo python3 /opt/netscanner/scanner_service.py
```

## 📈 Performance

- Scans ~100 devices in 5-10 minutes
- Low CPU usage between scans
- MongoDB indexes for fast queries
- Hourly scans (configurable)

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

## 📄 License

MIT License

## 🙏 Credits

Inspired by professional network monitoring and industrial security solutions.
