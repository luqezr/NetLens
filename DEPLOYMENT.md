# Deployment Guide - NetLens on Debian

This guide will walk you through deploying the NetLens network monitoring solution on Debian/Ubuntu.

## 📋 Prerequisites

- Debian 11/12 or Ubuntu 20.04/22.04
- Root/sudo access
- Static IP address recommended
- At least 2GB RAM
- 20GB disk space

## 🚀 Quick Start Installation

### 1. Download and Prepare

```bash
# Clone or copy the project to your server
git clone <your-repo-url> network-scanner
cd network-scanner

# Make install script executable
chmod +x install.sh
```

### 2. Run Installation

```bash
# Run as root
sudo ./install.sh
```

The installation script will:
- Install all dependencies (Python, Node.js, MongoDB, nmap)
- Create `/opt/netscanner` directory
- Install Python and Node packages
- Create systemd services
- Configure MongoDB
- Start services

### 3. Configure Your Network

```bash
# Edit configuration
sudo nano /opt/netscanner/config.env
```

**Important:** Update `NETWORK_RANGES` with your actual network subnets:
```env
NETWORK_RANGES=192.168.1.0/24,10.0.10.0/24,172.16.0.0/16
```

### 4. Restart Services

```bash
sudo systemctl restart netlensscan.service
# Optional scanner service (only if you enabled it):
sudo systemctl restart netlens.service
```

### 5. Verify Installation

```bash
# Check services
sudo systemctl status netlens.service
sudo systemctl status netlensscan.service

# Check API
curl http://localhost:5000/health

# Check logs
sudo tail -f /opt/netscanner/logs/scanner.log
```

## 🎨 Frontend Installation

### Option 1: Development Mode (Testing)

```bash
cd /opt/netscanner/frontend
npm install
npm start
# Access at http://your-server-ip:3000
```

### Option 2: Production with Nginx (Recommended)

```bash
# Install Nginx
sudo apt-get install nginx

# Build frontend
cd /opt/netscanner/frontend
npm install
npm run build

# Copy to web root
sudo mkdir -p /var/www/netscanner
sudo cp -r build/* /var/www/netscanner/

# Configure Nginx
sudo nano /etc/nginx/sites-available/netscanner
```

**Nginx Configuration:**

```nginx
server {
    listen 80;
    server_name your-domain.com;  # or IP address
    
    root /var/www/netscanner;
    index index.html;

    # Frontend
    location / {
        try_files $uri $uri/ /index.html;
    }

    # API Proxy
    location /api {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }

    # Health endpoint
    location /health {
        proxy_pass http://localhost:5000;
    }
}
```

**Enable site:**

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/netscanner /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

**Access:** http://your-server-ip

### Option 3: HTTPS with Let's Encrypt (Production)

```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal is configured automatically
```

## 🔧 Manual Configuration

### MongoDB Security

```bash
# Connect to MongoDB
mongo

# Create admin user
use admin
db.createUser({
  user: "admin",
  pwd: "your-secure-password",
  roles: ["userAdminAnyDatabase", "readWriteAnyDatabase"]
})

# Create scanner user
use netscanner
db.createUser({
  user: "netscanner",
  pwd: "another-secure-password",
  roles: [{ role: "readWrite", db: "netscanner" }]
})
```

Update `/opt/netscanner/config.env`:
```env
MONGO_URI=mongodb://netscanner:another-secure-password@localhost:27017/netscanner
```

### Firewall Configuration

```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow API (if not using Nginx proxy)
sudo ufw allow 5000/tcp

# Enable firewall
sudo ufw enable
```

### Service Management

```bash
# Start services
sudo systemctl start netlens.service
sudo systemctl start netlensscan.service

# Stop services
sudo systemctl stop netlens.service
sudo systemctl stop netlensscan.service

# Restart services
sudo systemctl restart netlens.service
sudo systemctl restart netlensscan.service

# Enable auto-start on boot
sudo systemctl enable netlens.service
sudo systemctl enable netlensscan.service

# View logs
sudo journalctl -u netlens.service -f
sudo journalctl -u netlensscan.service -f
```

## 📊 Monitoring

### Check Scanner Status

```bash
# View recent scans
sudo tail -100 /opt/netscanner/logs/scanner.log

# Check MongoDB
mongo netscanner --eval "db.devices.countDocuments()"
```

### API Endpoints

```bash
# Health check
curl http://localhost:5000/health

# Get devices
curl http://localhost:5000/api/devices

# Get statistics
curl http://localhost:5000/api/stats

# Get alerts
curl http://localhost:5000/api/alerts
```

## 🔒 Security Hardening

### 1. Change Default Passwords

Edit `/opt/netscanner/config.env` and update MongoDB password.

### 2. Add API Authentication (Optional)

Install authentication middleware:

```bash
cd /opt/netscanner
npm install jsonwebtoken bcryptjs
```

### 3. Restrict Network Access

```bash
# Only allow from specific network
sudo ufw allow from 192.168.1.0/24 to any port 5000
```

### 4. SSL/TLS

Use Let's Encrypt (see above) or your own certificates.

## 🐛 Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u netlens.service -xe

# Verify permissions
sudo chown -R netlens:netlens /opt/netscanner

# Check Python dependencies
sudo -u root python3 -m pip list
```

### MongoDB connection issues

```bash
# Check MongoDB status
sudo systemctl status mongodb

# Test connection
mongo --eval "db.serverStatus()"

# Check config
cat /opt/netscanner/config.env
```

### No devices found

```bash
# Run manual scan
sudo python3 /opt/netscanner/scanner_service.py

# Check network ranges
cat /opt/netscanner/config.env | grep NETWORK_RANGES

# Verify nmap works
sudo nmap -sn 192.168.1.0/24
```

### Frontend not loading

```bash
# Check Nginx status
sudo systemctl status nginx

# Check Nginx logs
sudo tail -f /var/log/nginx/error.log

# Rebuild frontend
cd /opt/netscanner/frontend
npm run build
sudo cp -r build/* /var/www/netscanner/
```

## 📈 Performance Tuning

### For Large Networks (>500 devices)

**Increase scan timeout:**

Edit `scanner_service.py`:
```python
self.nm.scan(ip, arguments='-O -sV -T3 --host-timeout 180s')
```

**Increase MongoDB connection pool:**

Edit `database/mongo_manager.py`:
```python
self.client = MongoClient(mongo_uri, maxPoolSize=50)
```

**Add MongoDB indexes:**

```javascript
mongo netscanner --eval '
db.devices.createIndex({ "ip_address": 1 });
db.devices.createIndex({ "status": 1, "last_seen": -1 });
'
```

## 🔄 Updates

### Update Application

```bash
cd /opt/netscanner
git pull
pip3 install -r requirements.txt
npm install
sudo systemctl restart netlensscan.service netlens.service
```

### Update Frontend

```bash
cd /opt/netscanner/frontend
git pull
npm install
npm run build
sudo cp -r build/* /var/www/netscanner/
```

## 📱 Mobile Access

The web interface is responsive and works on mobile devices. Simply access via your browser:

- `http://your-server-ip` (HTTP)
- `https://your-domain.com` (HTTPS)

## 🔗 Integration

The API can be integrated with other systems:

```python
import requests

# Get devices
response = requests.get('http://your-server:5000/api/devices')
devices = response.json()['data']

# Get statistics
stats = requests.get('http://your-server:5000/api/stats').json()
```

## 📞 Support

- Check logs: `/opt/netscanner/logs/`
- View system logs: `journalctl -u netlensscan.service`
- MongoDB logs: `/var/log/mongodb/`
- Nginx logs: `/var/log/nginx/`

## ✅ Post-Installation Checklist

- [ ] Services running (netlensscan, netlens, mongodb, nginx)
- [ ] Configuration updated with correct network ranges
- [ ] Frontend accessible via browser
- [ ] First scan completed successfully
- [ ] Devices showing in dashboard
- [ ] Alerts working
- [ ] Firewall configured
- [ ] SSL certificate installed (production)
- [ ] MongoDB password changed
- [ ] Backup strategy in place

## 🎉 Done!

Your Network Scanner is now running! Access the web interface and start monitoring your network.
