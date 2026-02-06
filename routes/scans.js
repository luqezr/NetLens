const express = require('express');
const mongoose = require('mongoose');
const scanManager = require('../scan/scanManager');

const router = express.Router();

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

function computeOccurrences({ enabled, mode, intervalMinutes, exactAt, dailyAt, weeklyAt, weeklyDays, count = 10 }) {
  if (!enabled) return [];
  const now = new Date();
  const items = [];

  if (mode === 'exact') {
    if (!exactAt) return [];
    const d = new Date(exactAt);
    if (Number.isNaN(d.getTime())) return [];
    return [d];
  }

  if (mode === 'daily') {
    let next = computeNextDaily(now, dailyAt);
    if (!next) return [];
    for (let i = 0; i < count; i += 1) {
      items.push(new Date(next));
      next = new Date(next);
      next.setDate(next.getDate() + 1);
    }
    return items;
  }

  if (mode === 'weekly') {
    let cursor = now;
    for (let i = 0; i < count; i += 1) {
      const next = computeNextWeekly(cursor, weeklyDays, weeklyAt);
      if (!next) break;
      items.push(next);
      // Advance slightly past the found time to find the following occurrence.
      cursor = new Date(next.getTime() + 60 * 1000);
    }
    return items;
  }

  // interval
  const interval = Math.max(1, Math.min(1440, Number(intervalMinutes) || 60));
  const first = new Date(now.getTime() + interval * 60 * 1000);
  for (let i = 0; i < count; i += 1) {
    items.push(new Date(first.getTime() + i * interval * 60 * 1000));
  }
  return items;
}

function getDb() {
  if (!mongoose.connection || !mongoose.connection.db) {
    throw new Error('MongoDB not connected');
  }
  return mongoose.connection.db;
}

router.post('/run', async (req, res) => {
  try {
    const requestedBy = req.body?.requested_by || req.ip;

    const networkRanges = (req.body?.network_ranges || req.body?.networkRanges || '').toString().trim();
    const options = req.body?.options && typeof req.body.options === 'object' ? req.body.options : null;

    const requestId = networkRanges || options
      ? await scanManager.requestManualScanWithOptions({
          getDb,
          requested_by: requestedBy,
          network_ranges: networkRanges || null,
          options,
        })
      : await scanManager.requestManualScan({
          getDb,
          requested_by: requestedBy,
        });

    res.json({
      success: true,
      data: { request_id: requestId },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/stop', async (req, res) => {
  try {
    const requestedBy = req.body?.requested_by || req.ip;
    const result = await scanManager.forceStopAll({ getDb, requested_by: requestedBy });
    res.json({ success: true, data: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/suggest-network', async (req, res) => {
  try {
    const suggestions = scanManager.suggestNetworkRanges();
    res.json({ success: true, data: { suggestions } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/log', async (req, res) => {
  try {
    const since = req.query?.since;
    const limit = req.query?.limit;

    // Embedded mode: logs are captured from the spawned child process.
    const embedded = scanManager.getLiveLog({ since, limit });
    if (embedded && Array.isArray(embedded.items) && embedded.items.length > 0) {
      return res.json({ success: true, data: embedded });
    }

    // External scanner mode: logs are written to MongoDB by scanner_service.py.
    // Also use this as a fallback when embedded logs are empty (e.g. after restart or heartbeat timing).
    const db = getDb();
    const externalAlive = await scanManager.isExternalScannerAlive(db);
    const fromDb = await scanManager.getLiveLogFromDb({ getDb, since, limit });

    // Prefer DB results if they contain items or if the external scanner is alive.
    if ((fromDb && Array.isArray(fromDb.items) && fromDb.items.length > 0) || externalAlive) {
      return res.json({ success: true, data: fromDb });
    }

    // Nothing running / no logs
    return res.json({ success: true, data: embedded });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/schedule', async (req, res) => {
  try {
    const db = getDb();

    const schedule = await db
      .collection('settings')
      .findOne({ _id: 'scan_schedule' });

    const base = schedule || { _id: 'scan_schedule', enabled: false, interval_minutes: 60, mode: 'interval', exact_at: null, daily_at: null, weekly_at: null, weekly_days: [], network_ranges: null };
    const enabled = Boolean(base.enabled);
    const mode = ['interval', 'exact', 'daily', 'weekly'].includes(base.mode) ? base.mode : (base.mode === 'exact' ? 'exact' : 'interval');
    const interval = Math.max(1, Math.min(1440, Number(base.interval_minutes) || 60));

    const occurrences = computeOccurrences({
      enabled,
      mode,
      intervalMinutes: interval,
      exactAt: base.exact_at,
      dailyAt: base.daily_at,
      weeklyAt: base.weekly_at,
      weeklyDays: base.weekly_days,
      count: 10,
    });

    res.json({
      success: true,
      data: {
        ...base,
        mode,
        interval_minutes: interval,
        next_occurrences: occurrences,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.delete('/schedule', async (req, res) => {
  try {
    const db = getDb();

    const update = {
      _id: 'scan_schedule',
      enabled: false,
      interval_minutes: 60,
      mode: 'interval',
      exact_at: null,
      daily_at: null,
      weekly_at: null,
      weekly_days: [],
      network_ranges: null,
      updated_at: new Date(),
    };

    await db.collection('settings').updateOne(
      { _id: 'scan_schedule' },
      { $set: update, $setOnInsert: { created_at: new Date() } },
      { upsert: true }
    );

    // Apply immediately (don't wait for the next 60s refresh tick).
    try {
      await scanManager.refreshScheduleNow({ getDb });
    } catch {
      // ignore
    }

    res.json({ success: true, data: update });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/schedule', async (req, res) => {
  try {
    const db = getDb();
    const enabled = Boolean(req.body?.enabled);
    const intervalMinutesRaw = req.body?.interval_minutes;

    const networkRangesRaw = (req.body?.network_ranges || req.body?.networkRanges || '').toString().trim();
    // Store as a comma-separated list; empty means "use default NETWORK_RANGES".
    const network_ranges = networkRangesRaw ? networkRangesRaw : null;

    const modeRaw = String(req.body?.mode || '').trim().toLowerCase();
    const mode = ['interval', 'exact', 'daily', 'weekly'].includes(modeRaw) ? modeRaw : 'interval';

    // Optional: exact run time (one-shot). UI sends an ISO string.
    // If set, the server will enqueue a scan at or after that timestamp.
    const exactAtRaw = req.body?.exact_at || req.body?.exactAt || null;
    const dailyAtRaw = req.body?.daily_at || req.body?.dailyAt || null;
    const weeklyAtRaw = req.body?.weekly_at || req.body?.weeklyAt || null;
    const weeklyDaysRaw = req.body?.weekly_days || req.body?.weeklyDays || null;

    let intervalMinutes = null;
    if (intervalMinutesRaw !== undefined && intervalMinutesRaw !== null && intervalMinutesRaw !== '') {
      intervalMinutes = Number(intervalMinutesRaw);
      if (!Number.isFinite(intervalMinutes) || intervalMinutes < 1 || intervalMinutes > 1440) {
        return res.status(400).json({
          success: false,
          error: 'interval_minutes must be a number between 1 and 1440',
        });
      }
      intervalMinutes = Math.floor(intervalMinutes);
    }

    let exactAt = null;
    if (mode === 'exact') {
      if (!exactAtRaw) {
        return res.status(400).json({ success: false, error: 'exact_at is required when mode=exact' });
      }
      const d = new Date(exactAtRaw);
      if (Number.isNaN(d.getTime())) {
        return res.status(400).json({ success: false, error: 'exact_at must be a valid ISO datetime string' });
      }
      exactAt = d;
    }

    let dailyAt = null;
    if (mode === 'daily') {
      const tm = parseTimeOfDay(dailyAtRaw);
      if (!tm) {
        return res.status(400).json({ success: false, error: 'daily_at must be a time string like HH:MM (00:00-23:59) or h:MM AM/PM' });
      }
      dailyAt = `${String(tm.hour).padStart(2, '0')}:${String(tm.minute).padStart(2, '0')}`;
    }

    let weeklyAt = null;
    let weeklyDays = [];
    if (mode === 'weekly') {
      const tm = parseTimeOfDay(weeklyAtRaw);
      if (!tm) {
        return res.status(400).json({ success: false, error: 'weekly_at must be a time string like HH:MM (00:00-23:59) or h:MM AM/PM' });
      }
      weeklyAt = `${String(tm.hour).padStart(2, '0')}:${String(tm.minute).padStart(2, '0')}`;

      const raw = Array.isArray(weeklyDaysRaw) ? weeklyDaysRaw : (typeof weeklyDaysRaw === 'string' ? weeklyDaysRaw.split(',') : []);
      weeklyDays = raw
        .map((v) => Number(v))
        .filter((n) => Number.isInteger(n) && n >= 0 && n <= 6);
      weeklyDays = Array.from(new Set(weeklyDays)).sort((a, b) => a - b);
      if (weeklyDays.length === 0) {
        return res.status(400).json({ success: false, error: 'weekly_days must contain at least one weekday number (0=Sun..6=Sat)' });
      }
    }

    const update = {
      _id: 'scan_schedule',
      enabled,
      mode,
      interval_minutes: intervalMinutes ?? 60,
      exact_at: mode === 'exact' ? exactAt : null,
      daily_at: mode === 'daily' ? dailyAt : null,
      weekly_at: mode === 'weekly' ? weeklyAt : null,
      weekly_days: mode === 'weekly' ? weeklyDays : [],
      network_ranges,
      updated_at: new Date(),
    };

    await db.collection('settings').updateOne(
      { _id: 'scan_schedule' },
      { $set: update, $setOnInsert: { created_at: new Date() } },
      { upsert: true }
    );

    // Apply immediately (don't wait for the next 60s refresh tick).
    try {
      await scanManager.refreshScheduleNow({ getDb });
    } catch {
      // ignore
    }

    res.json({ success: true, data: update });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/status', async (req, res) => {
  try {
    const status = await scanManager.getStatus({ getDb });

    res.json({
      success: true,
      data: status,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Scan history (completed/failed scans + raw results)
router.get('/history', async (req, res) => {
  try {
    const db = getDb();
    const limitRaw = req.query?.limit;
    let limit = 50;
    if (limitRaw !== undefined) {
      const n = Number(limitRaw);
      if (Number.isFinite(n)) limit = Math.max(1, Math.min(500, Math.floor(n)));
    }

    const docs = await db
      .collection('scan_history')
      .find({})
      .sort({ started_at: -1 })
      .limit(limit)
      .project({ raw: 0, devices: 0, discovered_hosts: 0 })
      .toArray();

    const items = docs.map((d) => ({
      ...d,
      _id: d._id.toString(),
      scan_request_id: d.scan_request_id ? String(d.scan_request_id) : null,
    }));

    res.json({ success: true, data: items });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/history/:id', async (req, res) => {
  try {
    const db = getDb();
    const id = String(req.params.id || '').trim();
    if (!id || !id.match(/^[a-fA-F0-9]{24}$/)) {
      return res.status(400).json({ success: false, error: 'Invalid scan id' });
    }

    const doc = await db.collection('scan_history').findOne({ _id: new mongoose.Types.ObjectId(id) });
    if (!doc) {
      return res.status(404).json({ success: false, error: 'Scan not found' });
    }

    res.json({
      success: true,
      data: {
        ...doc,
        _id: doc._id.toString(),
        scan_request_id: doc.scan_request_id ? String(doc.scan_request_id) : null,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
