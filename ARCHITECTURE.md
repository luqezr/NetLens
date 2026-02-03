# Technology Stack & Architecture

## Overview

NetLens is a comprehensive network discovery and monitoring platform designed to continuously scan your network, identify devices, and provide visual insights.

## 🏗️ Architecture

```
┌───────────────────────────────────────- Packet capture analysis

## 📈 Key Features

| Feature | Status |
|---------|--------|
| Network Discovery | ✅ Full Support |
| Device Identification | ✅ Full Support |
| OS Detection | ✅ Full Support |
| Topology Mapping | ✅ Basic |
| Alerting | ✅ Full Support |
| Industrial Protocols | ⚠️ Planned |
| Vulnerability Assessment | ⚠️ Basic |
| Web Dashboard | ✅ Full Support |
| Cost | 💰 Free/Open Source |───┐
│                    Network Devices                       │
│  (Computers, Printers, Routers, IoT, Mobile devices)    │
└────────────────────┬────────────────────────────────────┘
                     │
                     │ ARP/ICMP/SNMP
                     │
┌────────────────────▼────────────────────────────────────┐
│             Python Scanner Service                       │
│  • nmap - Port scanning & OS detection                  │
│  • scapy - ARP discovery                                │
│  • APScheduler - Hourly scheduling                      │
└────────────────────┬────────────────────────────────────┘
                     │
                     │ Write device data
                     │
┌────────────────────▼────────────────────────────────────┐
│                  MongoDB Database                        │
│  Collections:                                            │
│  • devices - Device inventory                           │
│  • scan_history - Scan records                          │
│  • alerts - Notifications                               │
│  • topology - Network connections                       │
└────────────────────┬────────────────────────────────────┘
                     │
                     │ Read via Mongoose
                     │
┌────────────────────▼────────────────────────────────────┐
│              Node.js REST API (Express)                  │
│  Endpoints:                                              │
│  • /api/devices - Device management                     │
│  • /api/stats - Dashboard statistics                    │
│  • /api/topology - Network graph data                   │
│  • /api/alerts - Alert management                       │
└────────────────────┬────────────────────────────────────┘
                     │
                     │ HTTP/JSON
                     │
┌────────────────────▼────────────────────────────────────┐
│              React Frontend (SPA)                        │
│  • Material-UI - UI components                          │
│  • React Flow - Network topology visualization          │
│  • Recharts - Dashboard charts                          │
│  • React Router - Navigation                            │
└─────────────────────────────────────────────────────────┘
```

## 🛠️ Technology Stack

### Backend Scanner (Python)

**Why Python?**
- Excellent network libraries (nmap, scapy)
- Easy to write network scanning scripts
- Best support for security tools

**Key Libraries:**
- `python-nmap` - Network scanning and OS detection
- `scapy` - Packet manipulation and ARP scanning
- `apscheduler` - Scheduled scanning (hourly)
- `pymongo` - MongoDB driver
- `loguru` - Logging
- `python-dotenv` - Configuration management

### Database (MongoDB)

**Why MongoDB?**
- Flexible schema for varied device data
- Great for storing semi-structured data
- Fast for read-heavy workloads
- Easy horizontal scaling
- Good for time-series data (scan history)

**Collections:**
```javascript
devices {
  ip_address, mac_address, hostname, vendor,
  device_type, os, services[], connection,
  status, first_seen, last_seen, metadata
}

scan_history {
  scan_id, started_at, completed_at,
  statistics, status
}

alerts {
  device_id, alert_type, severity,
  title, message, acknowledged
}

topology {
  source_device_id, target_device_id,
  connection_type, details
}
```

### API Server (Node.js + Express)

**Why Node.js?**
- Fast and lightweight
- Great for building REST APIs
- Large ecosystem (npm)
- Easy to integrate with MongoDB
- Non-blocking I/O for real-time features

**Key Libraries:**
- `express` - Web framework
- `mongoose` - MongoDB ODM
- `cors` - Cross-origin support
- `helmet` - Security headers
- `morgan` - Request logging

### Frontend (React)

**Why React?**
- Most popular modern framework
- Component-based architecture
- Large ecosystem
- Great performance
- Excellent for dashboards

**Key Libraries:**
- `@mui/material` - Professional UI components
- `reactflow` - Network topology visualization
- `recharts` - Beautiful charts
- `react-router-dom` - Client-side routing
- `axios` - HTTP client

## 🎯 Key Features

### 1. Network Discovery
- **ARP Scanning** - Fast device discovery via ARP requests
- **Port Scanning** - Identify running services (HTTP, SSH, FTP, etc.)
- **OS Detection** - Determine operating system and version
- **Vendor Identification** - MAC address lookup for manufacturer

### 2. Device Classification
Automatically classifies devices into categories:
- Windows PCs
- Linux servers
- Mac computers
- Mobile devices (iOS/Android)
- Network equipment (routers, switches)
- IoT devices
- Printers
- Unknown devices

### 3. Connection Detection
- Wired vs Wireless identification
- SSID for wireless devices
- Signal strength monitoring
- Access point association

### 4. Continuous Monitoring
- Scheduled scans every hour
- Automatic offline detection
- Change tracking
- Historical data retention

### 5. Alerting System
- New device alerts
- Offline device notifications
- Security concern alerts
- Customizable severity levels

### 6. Visualization
- **Dashboard** - Overview with statistics and charts
- **Device List** - Searchable table with all devices
- **Network Topology** - Interactive graph visualization
- **Alerts** - Notification management

## 🔄 Workflow

1. **Scanner Service** runs every hour (configurable)
2. Performs ARP scan to discover active devices
3. For each device, performs detailed nmap scan
4. Detects OS, services, and connection type
5. Stores data in MongoDB (upsert)
6. Marks devices not seen as offline
7. Creates alerts for new/offline devices
8. API serves data to frontend
9. Frontend displays real-time dashboard

## ⚡ Performance

### Scanning Speed
- ~100 devices scanned in 5-10 minutes
- Parallel scanning with timeout controls
- Adjustable scan intensity (T3-T5)

### Resource Usage
- Python service: ~50-100MB RAM (idle)
- API server: ~100MB RAM
- MongoDB: ~200MB+ RAM (depends on data)
- Scans: CPU spike during scan, then idle

### Scalability
- Handles networks up to 10,000 devices
- MongoDB sharding for larger deployments
- Load balancer for multiple API instances
- Can run multiple scanner instances

## 🔐 Security Considerations

### Scanner
- Requires root privileges (for raw socket access)
- Runs as systemd service with limited permissions
- Logs all activities
- Rate limiting to avoid network congestion

### API
- CORS enabled (configure for production)
- Helmet for security headers
- Input validation
- Rate limiting (recommended)
- JWT authentication (optional add-on)

### Database
- Authentication enabled
- User-level access control
- Network binding restrictions
- Regular backups

### Frontend
- No sensitive data stored
- API calls over HTTPS (production)
- Input sanitization
- XSS protection

## 🚀 Deployment Options

### Single Server (Small Networks)
```
Everything on one Debian server
Network: <1000 devices
Hardware: 4GB RAM, 2 CPUs
```

### Distributed (Large Networks)
```
Scanner Server: Debian with Python
Database Server: MongoDB dedicated
API Server: Node.js
Frontend: Nginx static hosting
Network: 1000-10000 devices
```

### High Availability
```
Multiple scanner instances
MongoDB replica set
Load-balanced API servers
CDN for frontend
```

## 📊 Data Flow

```
Network → Scanner → MongoDB → API → Frontend → User
   ↑         ↓                  ↓
   └─────────┴──────────────────┴──── Continuous loop
```

## 🔮 Future Enhancements

- SNMP support for switches (port mapping)
- Vulnerability scanning integration
- Traffic analysis
- Device profiling with ML
- Compliance reporting
- Email/SMS notifications
- Multi-tenancy support
- Packet capture analysis
- Asset management integration

## 📈 Key Features

| Feature | Status |
|---------|--------|
| Network Discovery | ✅ Full Support |
| Device Identification | ✅ Full Support |
| OS Detection | ✅ Full Support |
| Topology Mapping | ✅ Basic |
| Alerting | ✅ Full Support |
| Industrial Protocols | ⚠️ Planned |
| Vulnerability Assessment | ⚠️ Basic |
| Web Dashboard | ✅ Full Support |
| Cost | 💰 Free/Open Source |

## 💡 Best Use Cases

✅ **Perfect For:**
- Small to medium business networks
- Home labs and testing environments
- IT asset discovery
- Network documentation
- Security auditing
- BYOD monitoring

❌ **Not Ideal For:**
- Industrial control systems (requires additional protocols)
- Mission-critical infrastructure
- Networks requiring compliance (without customization)
- Real-time threat detection

## 🎓 Learning Resources

This project is great for learning:
- Network protocols (ARP, ICMP, TCP)
- Python for security/networking
- REST API design
- MongoDB data modeling
- React frontend development
- System administration
- DevOps practices

---

**Congratulations!** You now have NetLens, a professional network monitoring solution that is open source and fully customizable!
