const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

function exists(p) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

function getPythonPath() {
  if (process.env.SCANNER_PYTHON && exists(process.env.SCANNER_PYTHON)) {
    return process.env.SCANNER_PYTHON;
  }
  if (exists('/opt/netlens/venv/bin/python')) return '/opt/netlens/venv/bin/python';
  return 'python3';
}

function getScannerScriptPath() {
  if (process.env.SCANNER_SCRIPT && exists(process.env.SCANNER_SCRIPT)) {
    return process.env.SCANNER_SCRIPT;
  }
  if (exists('/opt/netlens/scanner_service.py')) return '/opt/netlens/scanner_service.py';
  return path.join(__dirname, '..', 'scanner_service.py');
}

function getEnvFile() {
  if (process.env.ENV_FILE && exists(process.env.ENV_FILE)) return process.env.ENV_FILE;
  if (exists('/opt/netlens/config.env')) return '/opt/netlens/config.env';
  return undefined;
}

function canWriteDir(dirPath) {
  try {
    fs.accessSync(dirPath, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

function canWriteFile(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      fs.accessSync(filePath, fs.constants.W_OK);
      return true;
    }
    const parent = path.dirname(filePath);
    fs.accessSync(parent, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

let state = {
  running: false,
  current_request_id: null,
  current_child_pid: null,
  last_started_at: null,
  last_finished_at: null,
  last_exit_code: null,
  last_error: null,
  last_stdout: null,
  last_stderr: null,
  log_cursor: 0,
  log_buffer: [],
  next_scheduled_at: null,
  schedule: { enabled: false, interval_minutes: 60 },
};

let currentChild = null;

function pushLog({ stream, text }) {
  if (!text) return;
  const lines = String(text).split(/\r?\n/);
  for (const line of lines) {
    if (!line) continue;
    state.log_cursor += 1;
    state.log_buffer.push({
      id: state.log_cursor,
      ts: new Date(),
      stream: stream || 'stdout',
      text: line,
      request_id: state.current_request_id,
    });
  }
  // Keep a rolling buffer (last ~2000 lines)
  if (state.log_buffer.length > 2000) {
    state.log_buffer = state.log_buffer.slice(-2000);
  }
}

let scheduleTimer = null;
let scheduleRefreshTimer = null;

function isTruthy(value) {
  if (value === true) return true;
  const s = String(value || '').trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

async function getScannerHeartbeat(db) {
  try {
    return await db.collection('settings').findOne({ _id: 'scanner_heartbeat' });
  } catch {
    return null;
  }
}

async function isExternalScannerAlive(db) {
  // Allow forcing embedded mode (useful for dev)
  if (isTruthy(process.env.SCAN_EMBEDDED_ONLY)) return false;

  const hb = await getScannerHeartbeat(db);
  const ts = hb?.updated_at ? new Date(hb.updated_at).getTime() : 0;
  if (!Number.isFinite(ts) || ts <= 0) return false;

  const maxAgeMs = Number(process.env.SCANNER_HEARTBEAT_MAX_AGE_MS || 45_000);
  const maxAge = Number.isFinite(maxAgeMs) ? Math.max(5_000, Math.min(10 * 60_000, maxAgeMs)) : 45_000;
  return Date.now() - ts <= maxAge;
}

function getStaleMinutes() {
  const raw = process.env.SCAN_STALE_MINUTES;
  const n = raw ? Number(raw) : 180;
  if (!Number.isFinite(n) || n < 10) return 180;
  return Math.floor(n);
}

async function reapStaleRunning(db) {
  const staleMinutes = getStaleMinutes();
  const cutoff = new Date(Date.now() - staleMinutes * 60 * 1000);

  const res = await db.collection('scan_requests').updateMany(
    { status: 'running', started_at: { $lt: cutoff } },
    {
      $set: {
        status: 'failed',
        completed_at: new Date(),
        error: `Marked failed: stale running request older than ${staleMinutes} minutes`,
      },
    }
  );

  return res.modifiedCount || 0;
}

async function getScheduleSettings(db) {
  const doc = await db.collection('settings').findOne({ _id: 'scan_schedule' });
  if (!doc) return { enabled: false, interval_minutes: 60 };
  return {
    enabled: Boolean(doc.enabled),
    interval_minutes: Number(doc.interval_minutes) || 60,
  };
}

async function enqueueScan(db, { type, requested_by, network_ranges, options }) {
  const doc = {
    type,
    status: 'queued',
    requested_by: requested_by || null,
    requested_at: new Date(),
    started_at: null,
    completed_at: null,
    network_ranges: network_ranges || null,
    options: options || null,
    result: null,
    error: null,
  };
  const result = await db.collection('scan_requests').insertOne(doc);
  return result.insertedId;
}

async function claimNextQueued(db) {
  return db.collection('scan_requests').findOneAndUpdate(
    { status: 'queued' },
    { $set: { status: 'running', started_at: new Date() } },
    { sort: { requested_at: 1 }, returnDocument: 'after' }
  );
}

function normalizeFindOneAndUpdateResult(result) {
  if (!result) return null;
  // Some drivers return { value: doc }, others return the doc directly.
  if (result.value) return result.value;
  if (result._id) return result;
  return null;
}

function runPythonOnce({ reason, scan_request_id, network_ranges, options }) {
  return new Promise((resolve, reject) => {
    const python = getPythonPath();
    const script = getScannerScriptPath();

    const env = { ...process.env };
    const envFile = getEnvFile();
    if (envFile) env.ENV_FILE = envFile;
    env.SCAN_REASON = reason || '';
    if (scan_request_id) env.SCAN_REQUEST_ID = String(scan_request_id);
    if (network_ranges) env.NETWORK_RANGES = String(network_ranges);

    // Optional scan knobs provided by UI.
    if (options && typeof options === 'object') {
      if (options.nmap_args) env.SCAN_NMAP_ARGS = String(options.nmap_args);
      if (options.top_ports) env.SCAN_TOP_PORTS = String(options.top_ports);
      if (options.host_timeout) env.SCAN_HOST_TIMEOUT = String(options.host_timeout);
      if (options.max_retries !== undefined && options.max_retries !== null) env.SCAN_MAX_RETRIES = String(options.max_retries);
      if (options.assume_up !== undefined && options.assume_up !== null) env.SCAN_ASSUME_UP = String(options.assume_up ? '1' : '0');
      if (options.script_timeout) env.SCAN_SCRIPT_TIMEOUT = String(options.script_timeout);
      if (options.log_level) env.LOG_LEVEL = String(options.log_level);
    }

    // Avoid noisy PermissionError when the API runs as a normal user.
    // If LOG_FILE is set but not writable, override it.
    // Also prefer a separate log file for API-triggered scans so we don't fight with a root-owned scanner.log.
    const isRoot = typeof process.getuid === 'function' ? process.getuid() === 0 : false;
    const optLogDir = '/opt/netlens/logs';
    const preferred = isRoot ? 'scanner.log' : 'scanner-ui.log';
    const desired = canWriteDir(optLogDir)
      ? path.join(optLogDir, preferred)
      : path.join(os.tmpdir(), preferred);

    if (!env.LOG_FILE || !canWriteFile(env.LOG_FILE)) {
      env.LOG_FILE = desired;
    }

    const child = spawn(python, [script, '--run-once'], {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    currentChild = child;
    state.current_child_pid = child.pid || null;

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (d) => {
      const s = d.toString();
      stdout += s;
      if (stdout.length > 20000) stdout = stdout.slice(-20000);
      pushLog({ stream: 'stdout', text: s });
      const prefix = state.current_request_id ? `[scanner ${state.current_request_id} stdout] ` : '[scanner stdout] ';
      process.stdout.write(prefix + s);
    });
    child.stderr.on('data', (d) => {
      const s = d.toString();
      stderr += s;
      if (stderr.length > 20000) stderr = stderr.slice(-20000);
      pushLog({ stream: 'stderr', text: s });
      const prefix = state.current_request_id ? `[scanner ${state.current_request_id} stderr] ` : '[scanner stderr] ';
      process.stderr.write(prefix + s);
    });

    child.on('error', (err) => reject(err));
    child.on('close', (code) => {
      if (currentChild === child) {
        currentChild = null;
        state.current_child_pid = null;
      }
      resolve({ code, stdout, stderr });
    });
  });
}

async function processQueue(db) {
  // If the privileged scanner service is running, it will pick up queued requests.
  // Avoid running scans in the API process (often unprivileged), which reduces discovery coverage.
  if (await isExternalScannerAlive(db)) {
    return;
  }
  if (state.running) return;

  // Try to claim a request
  const claimed = await claimNextQueued(db);
  const request = normalizeFindOneAndUpdateResult(claimed);
  if (!request) return;

  state.running = true;
  state.current_request_id = request._id.toString();
  state.log_buffer = [];
  state.last_started_at = new Date();
  state.last_error = null;
  state.last_stdout = null;
  state.last_stderr = null;

  console.log(`🧭 Scan started (request=${state.current_request_id}, type=${request.type})`);

  try {
    const networkRanges = request.network_ranges || null;
    const options = request.options || null;

    // Record network ranges on the request so the UI can show it in /scans/status.
    if (networkRanges) {
      await db.collection('scan_requests').updateOne(
        { _id: request._id },
        { $set: { network_ranges: networkRanges } }
      );
    }

    const runResult = await runPythonOnce({
      reason: request.type,
      scan_request_id: request._id.toString(),
      network_ranges: networkRanges,
      options,
    });
    state.last_exit_code = runResult.code;
    state.last_finished_at = new Date();
    state.last_stdout = runResult.stdout ? runResult.stdout.slice(-5000) : '';
    state.last_stderr = runResult.stderr ? runResult.stderr.slice(-5000) : '';

    console.log(`✅ Scan finished (request=${state.current_request_id}, exit_code=${runResult.code})`);

    if (runResult.code === 0) {
      await db.collection('scan_requests').updateOne(
        { _id: request._id },
        {
          $set: {
            status: 'completed',
            completed_at: new Date(),
            result: { exit_code: runResult.code },
            error: null,
          },
        }
      );
    } else {
      await db.collection('scan_requests').updateOne(
        { _id: request._id },
        {
          $set: {
            status: 'failed',
            completed_at: new Date(),
            error: `Scanner exited with code ${runResult.code}`,
            result: {
              exit_code: runResult.code,
              stderr: runResult.stderr.slice(-5000)
            },
          },
        }
      );
    }
  } catch (err) {
    state.last_error = err?.message || String(err);
    state.last_finished_at = new Date();
    console.error(`❌ Scan failed (request=${state.current_request_id}): ${state.last_error}`);
    await db.collection('scan_requests').updateOne(
      { _id: request._id },
      {
        $set: {
          status: 'failed',
          completed_at: new Date(),
          error: state.last_error,
        },
      }
    );
  } finally {
    state.running = false;
    state.current_request_id = null;
  }

  // Continue processing if more are queued
  await processQueue(db);
}

async function refreshSchedule(db) {
  const next = await getScheduleSettings(db);
  state.schedule = next;

  if (scheduleTimer) {
    clearInterval(scheduleTimer);
    scheduleTimer = null;
  }

  if (!next.enabled) {
    state.next_scheduled_at = null;
    return;
  }

  const intervalMs = Math.max(1, Math.min(1440, next.interval_minutes)) * 60 * 1000;
  state.next_scheduled_at = new Date(Date.now() + intervalMs);

  // If external scanner is alive, let it handle scheduling to avoid double-enqueue.
  if (await isExternalScannerAlive(db)) {
    return;
  }

  scheduleTimer = setInterval(async () => {
    try {
      await enqueueScan(db, { type: 'scheduled', requested_by: 'server' });
      console.log(`⏱️ Scheduled scan enqueued (every ${Math.max(1, Math.min(1440, next.interval_minutes))} min)`);
      await processQueue(db);
      state.next_scheduled_at = new Date(Date.now() + intervalMs);
    } catch {
      // ignore
    }
  }, intervalMs);
}

function init({ getDb }) {
  if (scheduleRefreshTimer) return;

  const tick = async () => {
    try {
      const db = getDb();
      await reapStaleRunning(db);
      await refreshSchedule(db);
      await processQueue(db);
    } catch {
      // ignore
    }
  };

  // Initial
  tick();

  // Refresh schedule every minute
  scheduleRefreshTimer = setInterval(tick, 60 * 1000);
}

async function requestManualScan({ getDb, requested_by }) {
  const db = getDb();
  const id = await enqueueScan(db, { type: 'manual', requested_by });
  console.log(`🟦 Manual scan requested (request=${id.toString()}, by=${requested_by || 'unknown'})`);

  // Fire-and-forget processing so the HTTP request can return immediately.
  // Skip if external scanner service is active.
  setImmediate(() => {
    processQueue(db).catch((e) => console.error('❌ Failed to process scan queue:', e));
  });
  return id.toString();
}

async function requestManualScanWithOptions({ getDb, requested_by, network_ranges, options }) {
  const db = getDb();
  const id = await enqueueScan(db, { type: 'manual', requested_by, network_ranges, options });
  console.log(`🟦 Manual scan requested (request=${id.toString()}, by=${requested_by || 'unknown'}, ranges=${network_ranges || 'default'})`);

  setImmediate(() => {
    processQueue(db).catch((e) => console.error('❌ Failed to process scan queue:', e));
  });

  return id.toString();
}

async function forceStopAll({ getDb, requested_by }) {
  const db = getDb();

  // Cancel queued requests.
  await db.collection('scan_requests').updateMany(
    { status: 'queued' },
    { $set: { status: 'cancelled', completed_at: new Date(), error: `Cancelled by ${requested_by || 'user'}` } }
  );

  // If we have a live child process, terminate it.
  const runningRequestId = state.current_request_id;
  const child = currentChild;
  if (child && !child.killed) {
    try {
      pushLog({ stream: 'stderr', text: `Force stop requested by ${requested_by || 'user'}` });
      child.kill('SIGTERM');
      // Escalate if needed.
      setTimeout(() => {
        try {
          if (currentChild === child && !child.killed) child.kill('SIGKILL');
        } catch {
          // ignore
        }
      }, 3000);
    } catch {
      // ignore
    }
  }

  // Mark any running requests as failed (whether or not we had a child handle).
  await db.collection('scan_requests').updateMany(
    { status: 'running' },
    { $set: { status: 'failed', completed_at: new Date(), error: `Force stopped by ${requested_by || 'user'}` } }
  );

  // Reset local state for UI.
  state.running = false;
  state.current_request_id = null;
  state.last_error = `Force stopped by ${requested_by || 'user'}`;

  return { stopped_request_id: runningRequestId || null };
}

function getLiveLog({ since, limit } = {}) {
  const sinceId = since ? Number(since) : 0;
  const max = Number.isFinite(Number(limit)) ? Math.max(1, Math.min(2000, Number(limit))) : 400;
  const items = state.log_buffer.filter((l) => l.id > sinceId).slice(-max);
  const nextSince = items.length > 0 ? items[items.length - 1].id : sinceId;
  return {
    items,
    next_since: nextSince,
    running: Boolean(state.running),
    current_request_id: state.current_request_id,
    current_child_pid: state.current_child_pid,
    timestamp: new Date(),
    source: 'embedded',
  };
}

async function getLiveLogFromDb({ getDb, since, limit } = {}) {
  const db = getDb();

  // Prefer the currently-running request, else most recently-updated one with logs.
  const runningReq = await db
    .collection('scan_requests')
    .find({ status: 'running' })
    .sort({ started_at: -1 })
    .limit(1)
    .toArray();

  let req = runningReq[0] || null;
  if (!req) {
    const recentWithLogs = await db
      .collection('scan_requests')
      .find({ live_log: { $exists: true, $ne: [] } })
      .sort({ updated_at: -1 })
      .limit(1)
      .toArray();
    req = recentWithLogs[0] || null;
  }

  const running = req ? req.status === 'running' : false;
  const requestId = req?._id ? req._id.toString() : null;

  const sinceId = since ? Number(since) : 0;
  const max = Number.isFinite(Number(limit)) ? Math.max(1, Math.min(2000, Number(limit))) : 400;

  const log = Array.isArray(req?.live_log) ? req.live_log : [];
  const items = log.filter((l) => (Number(l?.id) || 0) > sinceId).slice(-max);
  const nextSince = items.length > 0 ? Number(items[items.length - 1].id) : sinceId;

  return {
    items,
    next_since: nextSince,
    running,
    current_request_id: requestId,
    current_child_pid: null,
    timestamp: new Date(),
    source: 'mongodb',
  };
}

function suggestNetworkRanges() {
  const nets = os.networkInterfaces();
  const results = [];

  for (const name of Object.keys(nets || {})) {
    for (const addr of nets[name] || []) {
      if (!addr || addr.internal) continue;
      if (addr.family !== 'IPv4') continue;
      const ip = addr.address;
      // Best-effort: suggest /24 based on current interface IP.
      const parts = ip.split('.');
      if (parts.length !== 4) continue;
      results.push({
        interface: name,
        ip,
        cidr: `${parts[0]}.${parts[1]}.${parts[2]}.0/24`,
      });
    }
  }

  // De-dupe cidr suggestions.
  const seen = new Set();
  const unique = [];
  for (const r of results) {
    if (seen.has(r.cidr)) continue;
    seen.add(r.cidr);
    unique.push(r);
  }
  return unique;
}

async function getStatus({ getDb }) {
  const db = getDb();
  const external_scanner_alive = await isExternalScannerAlive(db);
  const scanner_heartbeat = await getScannerHeartbeat(db);
  const latestHistory = await db
    .collection('scan_history')
    .find({})
    .sort({ started_at: -1 })
    .limit(1)
    .project({ devices: 0, raw: 0, discovered_hosts: 0 })
    .toArray();

  const queued = await db.collection('scan_requests').countDocuments({ status: 'queued' });
  const running = await db.collection('scan_requests').countDocuments({ status: 'running' });

  const runningRequest = await db
    .collection('scan_requests')
    .find({ status: 'running' })
    .sort({ started_at: -1 })
    .limit(1)
    .toArray();

  const current_request = runningRequest[0] || null;

  const warnings = [];
  if (!state.running && running > 0) {
    warnings.push(
      'Scan requests are marked running in MongoDB, but no scan is active in this server process. This can happen after a crash/restart; stale requests will be auto-failed after SCAN_STALE_MINUTES.'
    );
  }

  return {
    ...state,
    external_scanner_alive,
    scanner_heartbeat,
    latest_scan: latestHistory[0] || null,
    current_request,
    // Back-compat naming for UI/API clients
    pending_requests: queued,
    queued_requests: queued,
    running_requests: running,
    warnings,
    timestamp: new Date(),
  };
}

module.exports = {
  init,
  requestManualScan,
  requestManualScanWithOptions,
  getStatus,
  forceStopAll,
  getLiveLog,
  getLiveLogFromDb,
  suggestNetworkRanges,
  // Exposed for routes that need to decide between embedded vs external scanner.
  isExternalScannerAlive,
  getScannerHeartbeat,
};
