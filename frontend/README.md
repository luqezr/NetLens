# NetLens Frontend

Modern React-based web interface for the NetLens network monitoring platform.

## Features

- 📊 Real-time dashboard with statistics
- 🔍 Device discovery and management
- 🗺️ Interactive network topology visualization
- 🔔 Alert management system
- 📱 Responsive design

## Installation

```bash
cd frontend
npm install
```

## Development

```bash
npm start
# Opens http://localhost:3000
```

## Production Build

```bash
npm run build
# Creates optimized build in build/ directory
```

## Deployment

### Option 1: Nginx (Recommended for Production)

```bash
# Build the app
npm run build

# Copy to web server
sudo cp -r build/* /var/www/html/netscanner/

# Configure nginx
sudo nano /etc/nginx/sites-available/netscanner
```

Nginx config:
```nginx
server {
    listen 80;
    server_name your-domain.com;
    root /var/www/html/netscanner;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Option 2: Serve with Node.js

```bash
npm install -g serve
serve -s build -p 3000
```

## Project Structure

```
frontend/
├── public/
│   ├── index.html
│   └── favicon.ico
├── src/
│   ├── components/
│   │   ├── Dashboard.js       # Main dashboard
│   │   ├── DeviceList.js      # Device table
│   │   ├── NetworkTopology.js # Network graph
│   │   ├── AlertsList.js      # Alerts management
│   │   └── DeviceDetails.js   # Device details modal
│   ├── services/
│   │   └── api.js             # API client
│   ├── App.js                 # Main app component
│   └── index.js               # Entry point
└── package.json
```

## Configuration

Update API endpoint in `src/services/api.js` if needed:

```javascript
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';
```

## Technologies Used

- **React 18** - UI framework
- **Material-UI** - Component library
- **React Flow** - Network topology visualization
- **Recharts** - Dashboard charts
- **Axios** - HTTP client
- **React Router** - Navigation
