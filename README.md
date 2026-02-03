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

- Debian/Ubuntu Linux
- Root/sudo access (required for network scanning)
- MongoDB
- Python 3.8+
- Node.js 16+
- nmap, tcpdump

## 🚀 Quick Installation (Debian)

```bash
# Clone repository
git clone <your-repo>
cd Network\ Collector

# Run installation script (as root)
sudo bash install.sh

# Edit configuration
sudo nano /opt/netscanner/config.env
# Update NETWORK_RANGES with your network subnets

# Restart services
sudo systemctl restart netscanner api
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
MONGO_URI=mongodb://netscanner:password@localhost:27017/netscanner
MONGO_DB_NAME=netscanner

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

1. **Firewall**: Restrict API access to trusted networks
2. **Authentication**: Add JWT/OAuth authentication to API
3. **MongoDB**: Change default password
4. **HTTPS**: Use reverse proxy (nginx) with SSL
5. **Permissions**: Run scanner as root, API as limited user

## 🔧 Troubleshooting

### Check service status
```bash
sudo systemctl status netscanner
sudo systemctl status api
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
