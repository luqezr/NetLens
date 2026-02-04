const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');

const envPath =
  process.env.ENV_FILE ||
  (fs.existsSync('/opt/netlens/config.env') ? '/opt/netlens/config.env' : 'config.env');
require('dotenv').config({ path: envPath });

const session = require('express-session');
const MongoStore = require('connect-mongo');
const https = require('https');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const User = require('./models/User');
const requireAuth = require('./middleware/requireAuth');
const scanManager = require('./scan/scanManager');

const app = express();

// Middleware
app.use(helmet());
const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:3000';
app.use(
  cors({
    origin: corsOrigin,
    credentials: true,
  })
);
app.use(express.json());

const LOG_POLLING_ENDPOINTS = String(process.env.LOG_POLLING_ENDPOINTS || 'false').toLowerCase() === 'true';
const POLLING_PREFIXES = [
  '/api/scans/status',
  '/api/scans/schedule',
  '/api/stats',
  '/health',
  '/.well-known/appspecific/com.chrome.devtools.json',
];

app.use(
  morgan('combined', {
    skip: (req) => {
      if (LOG_POLLING_ENDPOINTS) return false;
      const url = req.originalUrl || req.url || '';
      return POLLING_PREFIXES.some((p) => url === p || url.startsWith(p + '?') || url.startsWith(p + '/'));
    },
  })
);

// Chrome DevTools may probe this URL; returning 204 avoids noisy 404s in console.
app.get('/.well-known/appspecific/com.chrome.devtools.json', (req, res) => {
  res.status(204).end();
});

app.set('trust proxy', 1);

const sessionSecret = process.env.APP_SESSION_SECRET || crypto.randomBytes(48).toString('hex');
if (!process.env.APP_SESSION_SECRET) {
  console.warn('⚠️ APP_SESSION_SECRET not set. Sessions will reset on restart. Set it in config.env');
}

function parseCookieSecure() {
  const raw = String(process.env.COOKIE_SECURE || '').toLowerCase().trim();
  if (raw === 'true' || raw === '1' || raw === 'yes') return true;
  if (raw === 'false' || raw === '0' || raw === 'no') return false;
  if (raw === 'auto') return 'auto';

  const httpsEnabled = String(process.env.ENABLE_HTTPS || 'false').toLowerCase() === 'true';
  return httpsEnabled ? 'auto' : false;
}

app.use(
  session({
    name: 'netlens.sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI || 'mongodb://localhost:27017/netlens',
      ttl: 60 * 60 * 24 * 7,
      autoRemove: 'native',
    }),
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: parseCookieSecure(),
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

const mongoUrl = process.env.MONGO_URI || 'mongodb://localhost:27017/netlens';

async function ensureDefaultUser() {
  const count = await User.countDocuments();
  if (count > 0) return;

  const defaultUsername = process.env.DEFAULT_ADMIN_USERNAME || 'admin';
  const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'Sudo123';
  const saltRounds = Number(process.env.BCRYPT_ROUNDS || 12);
  const passwordHash = await bcrypt.hash(defaultPassword, saltRounds);

  await User.create({
    username: defaultUsername,
    password_hash: passwordHash,
    display_name: 'Administrator',
    must_change_password: true,
  });

  console.log(`✅ Created default application user: ${defaultUsername}`);
  console.log('⚠️ Default password is set. Please change it after login.');
}

// MongoDB Connection + post-connect initialization
mongoose
  .connect(mongoUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(async () => {
    console.log('✅ MongoDB Connected');

    try {
      await ensureDefaultUser();
    } catch (e) {
      console.error('❌ Failed to create default user:', e);
    }

    // Server-owned scan orchestration (no separate scanner service required)
    try {
      scanManager.init({
        getDb: () => mongoose.connection.db,
      });
    } catch (e) {
      console.error('❌ Failed to initialize scan manager:', e);
    }
  })
  .catch((err) => console.error('❌ MongoDB Connection Error:', err));

// Auth routes (unprotected)
app.use('/api/auth', require('./routes/auth'));

// Routes
app.use('/api/devices', requireAuth, require('./routes/devices'));
app.use('/api/topology', requireAuth, require('./routes/topology'));
app.use('/api/alerts', requireAuth, require('./routes/alerts'));
app.use('/api/stats', requireAuth, require('./routes/stats'));
app.use('/api/scans', requireAuth, require('./routes/scans'));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date() });
});

// Optional: serve the React build from the same server (useful for production installs)
function resolveFrontendBuildDir() {
  const candidates = [
    '/opt/netscanner/frontend/build',
    path.join(__dirname, 'frontend', 'build'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(path.join(candidate, 'index.html'))) return candidate;
  }
  return null;
}

const frontendBuildDir = resolveFrontendBuildDir();
if (frontendBuildDir) {
  console.log(`✅ Serving frontend from ${frontendBuildDir}`);
  app.use(express.static(frontendBuildDir));

  // SPA fallback: let React Router handle client-side routes
  app.get(/^\/(?!api\/|health$).*/, (req, res) => {
    res.sendFile(path.join(frontendBuildDir, 'index.html'));
  });
}

// Start server
const PORT = Number(process.env.PORT || 5000);
const ENABLE_HTTPS = String(process.env.ENABLE_HTTPS || 'false').trim().toLowerCase() === 'true';
const HTTPS_PORT = Number(process.env.HTTPS_PORT || 5443);

const httpServer = app.listen(PORT, () => {
  console.log(`🚀 HTTP server running on port ${PORT}`);
});

httpServer.on('error', (err) => {
  if (err && err.code === 'EADDRINUSE') {
    console.error(`❌ Port ${PORT} is already in use.`);
    console.error('If you installed via install.sh, the netlensscan.service is likely already running.');
    console.error('Stop it with: sudo systemctl stop netlensscan.service');
    console.error('Or run this server on a different port: PORT=5001 npm start');
  } else {
    console.error('❌ HTTP server failed to start:', err);
  }
  process.exit(1);
});

if (ENABLE_HTTPS) {
  const certPath = process.env.TLS_CERT_PATH;
  const keyPath = process.env.TLS_KEY_PATH;
  if (!certPath || !keyPath) {
    console.error('❌ ENABLE_HTTPS=true but TLS_CERT_PATH/TLS_KEY_PATH not set');
  } else {
    try {
      try {
        if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
          console.warn(`⚠️ HTTPS enabled but TLS files do not exist; skipping HTTPS. cert=${certPath} key=${keyPath}`);
          console.warn('Set ENABLE_HTTPS=false, or ensure TLS_CERT_PATH/TLS_KEY_PATH point to valid files.');
          return;
        }
        fs.accessSync(certPath, fs.constants.R_OK);
        fs.accessSync(keyPath, fs.constants.R_OK);
      } catch {
        console.warn('⚠️ HTTPS enabled but TLS files are not readable by this user; skipping HTTPS.');
        console.warn(`cert=${certPath} key=${keyPath}`);
        console.warn('Set ENABLE_HTTPS=false for dev, or adjust TLS_CERT_PATH/TLS_KEY_PATH permissions/ownership.');
        return;
      }

      const options = {
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath),
      };
      const httpsServer = https.createServer(options, app);
      httpsServer.on('error', (err) => {
        console.error('❌ HTTPS server failed to start:', err);
      });
      httpsServer.listen(HTTPS_PORT, () => {
        console.log(`🔒 HTTPS server running on port ${HTTPS_PORT}`);
      });
    } catch (e) {
      console.warn('⚠️ Failed to start HTTPS server; continuing with HTTP only.');
      console.warn(e);
    }
  }
}