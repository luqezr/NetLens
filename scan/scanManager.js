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
  schedule: { enabled: false, interval_minutes: 60, mode: 'interval', exact_at: null, daily_at: null, weekly_at: null, weekly_days: [] },
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
let scheduleExactTimeout = null;
let scheduleRecurTimeout = null;

const MAX_TIMEOUT_MS = 2147483647; // Node.js setTimeout max (~24.8 days)

function parseTimeOfDay(raw) {
  const s = String(raw || '').trim();

  // 24-hour HH:MM
  let m = s.match(/^([01]?\d|2[0-3]):([0-5]\d)$/);
  if (m) return { hour: Number(m[1]), minute: Number(m[2]) };

  // 12-hour h:MM AM/PM
  m = s.match(/^(\d{1,2}):(\d{2})\s*([AaPp][Mm])$/);
  if (!m) return null;
  let hour = Number(m[1]);
  const minute = Number(m[2]);
  const ampm = String(m[3]).toLowerCase();
  if (!Number.isFinite(hour) || hour < 1 || hour > 12) return null;
  if (!Number.isFinite(minute) || minute < 0 || minute > 59) return null;
  if (ampm === 'pm' && hour !== 12) hour += 12;
  if (ampm === 'am' && hour === 12) hour = 0;
  return { hour, minute };
}

function computeNextDaily(now, timeStr) {
  const tm = parseTimeOfDay(timeStr);
  if (!tm) return null;
  const d = new Date(now);
  d.setSeconds(0, 0);
  d.setHours(tm.hour, tm.minute, 0, 0);
  if (d.getTime() <= now.getTime()) d.setDate(d.getDate() + 1);
  return d;
}

function computeNextWeekly(now, daysOfWeek, timeStr) {
  const tm = parseTimeOfDay(timeStr);
  if (!tm) return null;
  const days = Array.isArray(daysOfWeek) ? daysOfWeek.map((n) => Number(n)).filter((n) => Number.isInteger(n) && n >= 0 && n <= 6) : [];
  const set = new Set(days);
  if (set.size === 0) return null;

  // Search up to 8 days ahead to find the next matching weekday at the desired time.
  for (let offset = 0; offset <= 8; offset += 1) {
    const d = new Date(now);
    d.setDate(d.getDate() + offset);
    d.setSeconds(0, 0);
    d.setHours(tm.hour, tm.minute, 0, 0);

    const dow = d.getDay();
    if (!set.has(dow)) continue;
    if (d.getTime() <= now.getTime()) continue;
    return d;
  }

  return null;
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
    mode: ['interval', 'exact', 'daily', 'weekly'].includes(doc.mode) ? doc.mode : (doc.mode === 'exact' ? 'exact' : 'interval'),
    exact_at: doc.exact_at || null,
    daily_at: doc.daily_at || null,
    weekly_at: doc.weekly_at || null,
    weekly_days: Array.isArray(doc.weekly_days) ? doc.weekly_days : [],
    network_ranges: (doc.network_ranges ? String(doc.network_ranges) : null),
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

    // Avoid noisy PermissionError when running the API as a normal user (dev).
    // If LOG_FILE is explicitly set (e.g. via config.env) but isn't writable by this user,
    // override it to a writable temp location so scans don't log scary stack traces.
    const optLogDir = '/opt/netlens/logs';
    const tmpLog = path.join(os.tmpdir(), 'netlens-scanner.log');
    try {
      if (env.LOG_FILE) {
        const dir = path.dirname(String(env.LOG_FILE));
        if (!canWriteDir(dir)) {
          env.LOG_FILE = tmpLog;
        }
      } else if (canWriteDir(optLogDir)) {
        env.LOG_FILE = path.join(optLogDir, 'scanner.log');
      } else {
        env.LOG_FILE = tmpLog;
      }
    } catch {
      env.LOG_FILE = tmpLog;
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
  // If a privileged external scanner is alive (scanner_service.py as root),
  // do not claim/execute requests in this Node process.
  try {
    if (await isExternalScannerAlive(db)) return;
  } catch {
    // ignore and fall back to local processing
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

  // If we had a computed next run time and it is overdue, enqueue it once.
  // This makes schedules robust even if long timers don't survive restarts.
  try {
    if (next.enabled && state.next_scheduled_at && state._schedule_due_fingerprint) {
      const dueAtMs = new Date(state.next_scheduled_at).getTime();
      const nowMs = Date.now();
      const isDue = Number.isFinite(dueAtMs) && nowMs >= dueAtMs;
      if (isDue && state._schedule_last_fired_fingerprint !== state._schedule_due_fingerprint) {
        const fp = state._schedule_due_fingerprint;
        state._schedule_last_fired_fingerprint = fp;
        await enqueueScan(db, { type: 'scheduled', requested_by: 'server', network_ranges: next.network_ranges || null });
        console.log(`🗓️ Scheduled scan enqueued (catch-up, due=${new Date(dueAtMs).toISOString()})`);
        try {
          await processQueue(db);
        } catch {
          // ignore
        }

        // One-shot exact schedule: auto-disable after it fires.
        if (next.mode === 'exact') {
          await db.collection('settings').updateOne(
            { _id: 'scan_schedule' },
            { $set: { enabled: false, updated_at: new Date() } },
            { upsert: true }
          );
          state.next_scheduled_at = null;
          state._schedule_due_fingerprint = null;
        } else {
          // Force recomputation of the next run time.
          state.next_scheduled_at = null;
          state._schedule_due_fingerprint = null;
        }
      }
    }
  } catch {
    // ignore; normal refresh below will still set timers
  }

  // If schedule is disabled, always clear the timer.
  if (!next.enabled) {
    if (scheduleTimer) {
      clearInterval(scheduleTimer);
      scheduleTimer = null;
    }
    if (scheduleExactTimeout) {
      clearTimeout(scheduleExactTimeout);
      scheduleExactTimeout = null;
    }
    if (scheduleRecurTimeout) {
      clearTimeout(scheduleRecurTimeout);
      scheduleRecurTimeout = null;
    }
    state.next_scheduled_at = null;
    state._schedule_interval_ms = null;
    state._schedule_exact_fingerprint = null;
    state._schedule_recur_fingerprint = null;
    state._schedule_due_fingerprint = null;
    return;
  }

  // Daily/weekly recurring schedules (calendar-based).
  if (next.mode === 'daily' || next.mode === 'weekly') {
    // Clear any interval timer.
    if (scheduleTimer) {
      clearInterval(scheduleTimer);
      scheduleTimer = null;
    }
    // Clear any one-shot exact timer.
    if (scheduleExactTimeout) {
      clearTimeout(scheduleExactTimeout);
      scheduleExactTimeout = null;
    }

    const now = new Date();
    const target = next.mode === 'daily'
      ? computeNextDaily(now, next.daily_at)
      : computeNextWeekly(now, next.weekly_days, next.weekly_at);

    if (!target || Number.isNaN(target.getTime())) {
      state.next_scheduled_at = null;
      return;
    }

    state.next_scheduled_at = target;
    const fingerprint = `${next.mode}:${target.getTime()}`;
    state._schedule_due_fingerprint = fingerprint;
    if (state._schedule_recur_fingerprint === fingerprint && scheduleRecurTimeout) {
      return;
    }
    state._schedule_recur_fingerprint = fingerprint;

    if (scheduleRecurTimeout) {
      clearTimeout(scheduleRecurTimeout);
      scheduleRecurTimeout = null;
    }

    const ms = Math.max(0, target.getTime() - Date.now());
    const armFire = (delayMs) => setTimeout(async () => {
      try {
        // Mark as fired before enqueue to avoid double fire in edge cases.
        state._schedule_last_fired_fingerprint = fingerprint;
        await enqueueScan(db, { type: 'scheduled', requested_by: 'server', network_ranges: next.network_ranges || null });
        console.log(`🗓️ Scheduled scan enqueued (${next.mode} at ${target.toISOString()})`);
        await processQueue(db);
      } catch {
        // ignore
      } finally {
        // Recompute next run immediately (don’t wait for the next 60s refresh tick).
        try {
          await refreshSchedule(db);
        } catch {
          // ignore
        }
      }
    }, delayMs);

    // Avoid exceeding Node's maximum setTimeout delay.
    if (ms > MAX_TIMEOUT_MS) {
      scheduleRecurTimeout = setTimeout(async () => {
        try {
          await refreshSchedule(db);
        } catch {
          // ignore
        }
      }, MAX_TIMEOUT_MS);
    } else {
      scheduleRecurTimeout = armFire(ms);
    }

    return;
  }

  // Calendar-based one-shot schedule.
  if (next.mode === 'exact' && next.exact_at) {
    const target = new Date(next.exact_at);
    if (Number.isNaN(target.getTime())) {
      state.next_scheduled_at = null;
      return;
    }

    // Clear any interval timer.
    if (scheduleTimer) {
      clearInterval(scheduleTimer);
      scheduleTimer = null;
    }

    // Clear any recurring calendar timer.
    if (scheduleRecurTimeout) {
      clearTimeout(scheduleRecurTimeout);
      scheduleRecurTimeout = null;
    }

    const ms = Math.max(0, target.getTime() - Date.now());
    state.next_scheduled_at = target;

    // Recreate one-shot timer only if timestamp changed.
    const fingerprint = String(target.getTime());
    state._schedule_due_fingerprint = `exact:${fingerprint}`;
    if (state._schedule_exact_fingerprint === fingerprint && scheduleExactTimeout) {
      return;
    }
    state._schedule_exact_fingerprint = fingerprint;

    if (scheduleExactTimeout) {
      clearTimeout(scheduleExactTimeout);
      scheduleExactTimeout = null;
    }

    const armFire = (delayMs) => setTimeout(async () => {
      try {
        state._schedule_last_fired_fingerprint = `exact:${fingerprint}`;
        await enqueueScan(db, { type: 'scheduled', requested_by: 'server', network_ranges: next.network_ranges || null });
        console.log(`🗓️ Scheduled scan enqueued (at ${target.toISOString()})`);
        await processQueue(db);

        // Auto-disable exact schedule after it fires (one-shot semantics).
        await db.collection('settings').updateOne(
          { _id: 'scan_schedule' },
          { $set: { enabled: false, updated_at: new Date() } },
          { upsert: true }
        );
        state.next_scheduled_at = null;
      } catch {
        // ignore
      }
    }, delayMs);

    if (ms > MAX_TIMEOUT_MS) {
      scheduleExactTimeout = setTimeout(async () => {
        try {
          await refreshSchedule(db);
        } catch {
          // ignore
        }
      }, MAX_TIMEOUT_MS);
    } else {
      scheduleExactTimeout = armFire(ms);
    }

    return;
  }

  const intervalMinutes = Math.max(1, Math.min(1440, next.interval_minutes));
  const intervalMs = intervalMinutes * 60 * 1000;

  // Don't recreate the timer every refresh tick; otherwise it never fires.
  const needsNewTimer = !scheduleTimer || state._schedule_interval_ms !== intervalMs;
  state._schedule_interval_ms = intervalMs;

  if (!state.next_scheduled_at || needsNewTimer) {
    state.next_scheduled_at = new Date(Date.now() + intervalMs);
  }

  state._schedule_due_fingerprint = `interval:${new Date(state.next_scheduled_at).getTime()}`;

  if (!needsNewTimer) return;

  if (scheduleTimer) {
    clearInterval(scheduleTimer);
    scheduleTimer = null;
  }

  scheduleTimer = setInterval(async () => {
    try {
      const fp = state._schedule_due_fingerprint;
      if (fp) state._schedule_last_fired_fingerprint = fp;
      await enqueueScan(db, { type: 'scheduled', requested_by: 'server', network_ranges: next.network_ranges || null });
      console.log(`⏱️ Scheduled scan enqueued (every ${intervalMinutes} min)`);
      await processQueue(db);
      state.next_scheduled_at = new Date(Date.now() + intervalMs);
      state._schedule_due_fingerprint = `interval:${state.next_scheduled_at.getTime()}`;
    } catch {
      // ignore
    }
  }, intervalMs);
}

async function refreshScheduleNow({ getDb }) {
  const db = getDb();
  await refreshSchedule(db);
  return { next_scheduled_at: state.next_scheduled_at, schedule: state.schedule };
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
  };
}

// Optional external-scanner support (DB-backed logs).
// This repo currently runs scans by spawning scanner_service.py and capturing stdout/stderr,
// so DB logs are best-effort and should never break the /api/scans/log endpoint.
async function isExternalScannerAlive(_db) {
  // Allow forcing local execution (useful for dev).
  const forceLocal = String(process.env.SCAN_FORCE_LOCAL_WORKER || '').trim().toLowerCase();
  if (forceLocal && !['0', 'false', 'no', 'off'].includes(forceLocal)) return false;

  try {
    const doc = await _db.collection('scanner_heartbeat').findOne({ _id: 'scanner' });
    if (!doc) return false;
    const ts = doc.ts ? new Date(doc.ts) : null;
    if (!ts || Number.isNaN(ts.getTime())) return false;

    // Only consider an external scanner “alive” if it's privileged (root) so OS/MAC detection works.
    if (doc.is_root === false) return false;

    const ageMs = Date.now() - ts.getTime();
    return ageMs >= 0 && ageMs < 45_000;
  } catch {
    return false;
  }
}

async function getLiveLogFromDb({ getDb, since, limit } = {}) {
  const sinceId = since ? Number(since) : 0;
  const nextSince = Number.isFinite(sinceId) && sinceId >= 0 ? sinceId : 0;
  const max = Number.isFinite(Number(limit)) ? Math.max(1, Math.min(2000, Number(limit))) : 400;

  if (typeof getDb !== 'function') {
    return {
      items: [],
      next_since: nextSince,
      running: false,
      current_request_id: null,
      current_child_pid: null,
      limit: max,
      timestamp: new Date(),
    };
  }

  const db = getDb();

  // Track the most recent running request (external scanner updates scan_requests).
  const runningReq = await db
    .collection('scan_requests')
    .find({ status: 'running' })
    .sort({ started_at: -1 })
    .limit(1)
    .toArray();

  const req = runningReq[0] || null;
  const requestId = req?._id || null;
  if (!requestId) {
    return {
      items: [],
      next_since: nextSince,
      running: false,
      current_request_id: null,
      current_child_pid: null,
      limit: max,
      timestamp: new Date(),
    };
  }

  const docs = await db
    .collection('scan_logs')
    .find({ request_id: requestId, seq: { $gt: nextSince } })
    .sort({ seq: 1 })
    .limit(max)
    .toArray();

  const items = (docs || []).map((d) => ({
    id: Number(d.seq) || 0,
    ts: d.ts || new Date(),
    stream: d.stream || 'info',
    text: d.text || '',
    request_id: requestId.toString(),
  }));

  const advanced = items.length > 0 ? items[items.length - 1].id : nextSince;
  return {
    items,
    next_since: advanced,
    running: true,
    current_request_id: requestId.toString(),
    current_child_pid: null,
    limit: max,
    timestamp: new Date(),
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

  // Important: do not leak Node timer handles into JSON responses.
  const { _schedule_exact_timeout, _schedule_recur_timeout, ...safeState } = state;

  return {
    ...safeState,
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
  refreshScheduleNow,
  getStatus,
  forceStopAll,
  getLiveLog,
  getLiveLogFromDb,
  isExternalScannerAlive,
  suggestNetworkRanges,
};
