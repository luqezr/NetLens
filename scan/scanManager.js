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

let state = {
  running: false,
  current_request_id: null,
  last_started_at: null,
  last_finished_at: null,
  last_exit_code: null,
  last_error: null,
  last_stdout: null,
  last_stderr: null,
  next_scheduled_at: null,
  schedule: { enabled: false, interval_minutes: 60 },
};

let scheduleTimer = null;
let scheduleRefreshTimer = null;

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

async function enqueueScan(db, { type, requested_by }) {
  const doc = {
    type,
    status: 'queued',
    requested_by: requested_by || null,
    requested_at: new Date(),
    started_at: null,
    completed_at: null,
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

function runPythonOnce({ reason }) {
  return new Promise((resolve, reject) => {
    const python = getPythonPath();
    const script = getScannerScriptPath();

    const env = { ...process.env };
    const envFile = getEnvFile();
    if (envFile) env.ENV_FILE = envFile;
    env.SCAN_REASON = reason || '';
    if (process.env.SCAN_REQUEST_ID) {
      env.SCAN_REQUEST_ID = process.env.SCAN_REQUEST_ID;
    }

    // Avoid noisy PermissionError when running the API as a normal user (dev).
    // The service user (netscanner) typically has write access to /opt/netlens/logs.
    if (!env.LOG_FILE) {
      const optLogDir = '/opt/netlens/logs';
      if (canWriteDir(optLogDir)) {
        env.LOG_FILE = path.join(optLogDir, 'scanner.log');
      } else {
        env.LOG_FILE = path.join(os.tmpdir(), 'netlens-scanner.log');
      }
    }

    const child = spawn(python, [script, '--run-once'], {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (d) => {
      const s = d.toString();
      stdout += s;
      if (stdout.length > 20000) stdout = stdout.slice(-20000);
      process.stdout.write(`[scanner stdout] ${s}`);
    });
    child.stderr.on('data', (d) => {
      const s = d.toString();
      stderr += s;
      if (stderr.length > 20000) stderr = stderr.slice(-20000);
      process.stderr.write(`[scanner stderr] ${s}`);
    });

    child.on('error', (err) => reject(err));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

async function processQueue(db) {
  if (state.running) return;

  // Try to claim a request
  const claimed = await claimNextQueued(db);
  const request = normalizeFindOneAndUpdateResult(claimed);
  if (!request) return;

  state.running = true;
  state.current_request_id = request._id.toString();
  state.last_started_at = new Date();
  state.last_error = null;
  state.last_stdout = null;
  state.last_stderr = null;

  console.log(`🧭 Scan started (request=${state.current_request_id}, type=${request.type})`);

  try {
    // Pass request id down so the scanner can update progress and attach raw results.
    const previousEnvScanRequestId = process.env.SCAN_REQUEST_ID;
    process.env.SCAN_REQUEST_ID = request._id.toString();
    const runResult = await runPythonOnce({ reason: request.type });
    if (previousEnvScanRequestId === undefined) {
      delete process.env.SCAN_REQUEST_ID;
    } else {
      process.env.SCAN_REQUEST_ID = previousEnvScanRequestId;
    }
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
  setImmediate(() => {
    processQueue(db).catch((e) => console.error('❌ Failed to process scan queue:', e));
  });
  return id.toString();
}

async function getStatus({ getDb }) {
  const db = getDb();
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
  getStatus,
};
