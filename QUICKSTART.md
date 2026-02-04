# Quick Start Guide - NetLens

Get your network monitoring solution running in 15 minutes!

## 🚀 Prerequisites

- Debian/Ubuntu server with root access
- Your network subnet (e.g., 192.168.1.0/24)

## ⚡ Installation (5 minutes)

```bash
# 1. Clone/download the project
cd /opt
git clone <your-repo> netscanner
cd netscanner

# 2. Run installation script
chmod +x install.sh
sudo ./install.sh

# Wait for installation to complete...
```

## ⚙️ Configuration (2 minutes)

```bash
# Edit config file
sudo nano /opt/netscanner/config.env
```

**Update this line with YOUR network:**
```env
NETWORK_RANGES=192.168.1.0/24
```

**Save and restart:**
```bash
sudo systemctl restart netlensscan.service
# Optional scanner service (only if you enabled it):
sudo systemctl restart netlens.service
```

## ✅ Verify (1 minute)

```bash
# Check services are running
sudo systemctl status netlens.service
sudo systemctl status netlensscan.service

# Test API
curl http://localhost:5000/health
# Should return: {"status":"OK","timestamp":"..."}

# Watch first scan
sudo tail -f /opt/netscanner/logs/scanner.log
```

## 🎨 Install Frontend (5 minutes)

### Option A: Quick Test (Development Mode)

```bash
cd /opt/netscanner/frontend
npm install
npm start
```

Access at: **http://your-server-ip:3000**

### Option B: Production (Nginx)

```bash
# Install Nginx
sudo apt-get install nginx -y

# Build frontend
cd /opt/netscanner/frontend
npm install
npm run build

# Deploy
sudo mkdir -p /var/www/netscanner
sudo cp -r build/* /var/www/netscanner/

# Configure Nginx
sudo tee /etc/nginx/sites-available/netscanner > /dev/null <<'EOF'
server {
    listen 80;
    server_name _;
    root /var/www/netscanner;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }

    location /health {
        proxy_pass http://localhost:5000;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/netscanner /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default  # Remove default site
sudo nginx -t
sudo systemctl restart nginx
```

Access at: **http://your-server-ip**

## 🎉 You're Done!

### What You Should See:

1. **Dashboard** - Overview with device counts and charts
2. **Devices** - List of all discovered devices
3. **Topology** - Network visualization
4. **Alerts** - New device notifications

### First Scan:

The first scan runs immediately, then every hour. It may take 5-10 minutes depending on your network size.

## 📱 Access From Anywhere

### On Your Computer:
```
http://your-debian-server-ip
```

### On Your Phone:
Open browser and go to the same URL. The interface is mobile-friendly!

## 🔧 Common Commands

```bash
# Restart services
sudo systemctl restart netlensscan.service netlens.service

# View logs
sudo journalctl -u netlensscan.service -f

# Manual scan
sudo python3 /opt/netscanner/scanner_service.py

# Check API
curl http://localhost:5000/api/devices | jq

# Update network ranges
sudo nano /opt/netscanner/config.env
sudo systemctl restart netlensscan.service
```

## 🐛 Troubleshooting

### No devices showing?

```bash
# Check your network range is correct
cat /opt/netscanner/config.env | grep NETWORK_RANGES

# Run manual scan
sudo python3 /opt/netscanner/scanner_service.py

# Check MongoDB
mongo netlens --eval "db.devices.find().pretty()"
```

### Frontend not loading?

```bash
# Check Nginx
sudo systemctl status nginx
sudo nginx -t

# Check API
curl http://localhost:5000/health

# Rebuild frontend
cd /opt/netscanner/frontend
npm run build
sudo cp -r build/* /var/www/netscanner/
```

### Services not starting?

```bash
# Check logs
sudo journalctl -u netlens.service -xe
sudo journalctl -u netlensscan.service -xe

# Check permissions
sudo chown -R root:root /opt/netscanner/scanner_service.py
sudo chown -R netlens:netlens /opt/netscanner
```

## 📊 What Gets Scanned?

For each device, the scanner detects:
- ✅ IP address
- ✅ MAC address
- ✅ Hostname
- ✅ Vendor (from MAC)
- ✅ Operating System
- ✅ Open ports and services
- ✅ Connection type (wired/wireless)
- ✅ Device type (PC, printer, router, etc.)

## 🔐 Security Notes

⚠️ **Important:**

1. **Change MongoDB password** (production)
2. **Use HTTPS** in production (Let's Encrypt)
3. **Configure firewall** to restrict access
4. **Scanner needs root** (for raw sockets)

## 📈 Next Steps

1. ✅ Verify devices are being discovered
2. ✅ Customize network ranges
3. ✅ Set up HTTPS (production)
4. ✅ Configure firewall
5. ✅ Set up backups
6. ✅ Add authentication (optional)

## 💡 Tips

- **Large Networks**: Adjust scan timeout in `scanner_service.py`
- **Frequent Scans**: Modify `SCAN_SCHEDULE` in config
- **Multiple Subnets**: Comma-separate in `NETWORK_RANGES`
- **Performance**: Increase MongoDB connection pool for 500+ devices

## 📚 Full Documentation

- **README.md** - Overview and features
- **ARCHITECTURE.md** - Technology stack details
- **DEPLOYMENT.md** - Complete deployment guide

## 🎯 Example Network Ranges

```env
# Single subnet
NETWORK_RANGES=192.168.1.0/24

# Multiple subnets
NETWORK_RANGES=192.168.1.0/24,192.168.2.0/24,10.0.0.0/24

# Large network
NETWORK_RANGES=10.0.0.0/16,172.16.0.0/16
```

## ✨ Features Overview

| Feature | Description |
|---------|-------------|
| 🔍 Auto Discovery | Finds all devices every hour |
| 📊 Dashboard | Real-time statistics |
| 🗺️ Topology | Visual network map |
| 🔔 Alerts | New/offline device notifications |
| 📱 Mobile Friendly | Works on phones/tablets |
| 🔒 Secure | Production-ready with HTTPS |

## 🆘 Need Help?

1. Check logs: `sudo journalctl -u netscanner -f`
2. Test components individually
3. Verify network connectivity
4. Check MongoDB is running
5. Review DEPLOYMENT.md for details

---

**🎊 Congratulations!** You now have NetLens, a professional network monitoring solution, running!

Your dashboard URL: **http://your-server-ip**

Happy monitoring! 🚀
