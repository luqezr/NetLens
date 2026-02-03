#!/bin/bash

# NetLens Installation Script for Debian
# This script installs and configures the NetLens network monitoring service

set -e

echo "====================================="
echo "NetLens Installation"
echo "====================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo ./install.sh)"
    exit 1
fi

# Update system
echo "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install dependencies
echo "Installing dependencies..."
apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    tcpdump \
    nodejs \
    npm \
    mongodb \
    git \
    curl

# Create application directory
echo "Creating application directory..."
mkdir -p /opt/netscanner
mkdir -p /opt/netscanner/logs
mkdir -p /opt/netscanner/database

# Copy application files
echo "Copying application files..."
cp -r ./* /opt/netscanner/

# Install Python dependencies
echo "Installing Python packages..."
cd /opt/netscanner
pip3 install -r requirements.txt

# Install Node.js dependencies
echo "Installing Node.js packages..."
npm install

# Create user for service
echo "Creating service user..."
if ! id -u netscanner > /dev/null 2>&1; then
    useradd -r -s /bin/false netscanner
fi

# Set permissions
echo "Setting permissions..."
chown -R netscanner:netscanner /opt/netscanner
chmod +x /opt/netscanner/scanner_service.py

# Configure MongoDB
echo "Starting MongoDB..."
systemctl enable mongodb
systemctl start mongodb

# Wait for MongoDB to start
sleep 5

# Create MongoDB database and user
echo "Configuring MongoDB..."
mongo --eval "
use netscanner;
db.createUser({
    user: 'netscanner',
    pwd: 'changeme_secure_password',
    roles: [{ role: 'readWrite', db: 'netscanner' }]
});
"

# Update config.env with MongoDB credentials
echo "Updating configuration..."
cat > /opt/netscanner/config.env << EOF
# MongoDB Configuration
MONGO_URI=mongodb://netscanner:changeme_secure_password@localhost:27017/netscanner
MONGO_DB_NAME=netscanner

# Network Settings (UPDATE THESE FOR YOUR NETWORK)
NETWORK_RANGES=192.168.1.0/24
SCAN_SCHEDULE=*/60 * * * *

# API Settings
PORT=5000
NODE_ENV=production

# Logging
LOG_FILE=/opt/netscanner/logs/scanner.log
LOG_LEVEL=INFO
EOF

# Install systemd services
echo "Installing systemd services..."
cp /opt/netscanner/netscanner.service /etc/systemd/system/
cp /opt/netscanner/api.service /etc/systemd/system/

# Reload systemd
systemctl daemon-reload

# Enable and start services
echo "Starting services..."
systemctl enable netscanner.service
systemctl enable api.service

systemctl start netscanner.service
systemctl start api.service

# Create cron job for hourly scans (alternative to service scheduler)
echo "Setting up cron job for hourly scans..."
(crontab -l 2>/dev/null; echo "0 * * * * /usr/bin/python3 /opt/netscanner/scanner_service.py >> /opt/netscanner/logs/cron.log 2>&1") | crontab -

echo ""
echo "====================================="
echo "Installation Complete!"
echo "====================================="
echo ""
echo "Services Status:"
systemctl status netscanner.service --no-pager
systemctl status api.service --no-pager
echo ""
echo "Configuration file: /opt/netscanner/config.env"
echo "Logs: /opt/netscanner/logs/"
echo ""
echo "API Server: http://localhost:5000"
echo "Health Check: curl http://localhost:5000/health"
echo ""
echo "Next Steps:"
echo "1. Edit /opt/netscanner/config.env with your network ranges"
echo "2. Change MongoDB password in config.env"
echo "3. Restart services: systemctl restart netscanner api"
echo "4. Install frontend (see frontend/README.md)"
echo ""
