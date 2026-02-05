const express = require('express');
const mongoose = require('mongoose');
const scanManager = require('../scan/scanManager');

const router = express.Router();

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

    const base = schedule || { _id: 'scan_schedule', enabled: false, interval_minutes: 60 };
    const enabled = Boolean(base.enabled);
    const interval = Math.max(1, Math.min(1440, Number(base.interval_minutes) || 60));
    const now = new Date();
    const next = enabled ? new Date(now.getTime() + interval * 60 * 1000) : null;
    const occurrences = [];
    if (enabled) {
      for (let i = 0; i < 10; i += 1) {
        occurrences.push(new Date(next.getTime() + i * interval * 60 * 1000));
      }
    }

    res.json({
      success: true,
      data: {
        ...base,
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
      updated_at: new Date(),
    };

    await db.collection('settings').updateOne(
      { _id: 'scan_schedule' },
      { $set: update, $setOnInsert: { created_at: new Date() } },
      { upsert: true }
    );

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

    const update = {
      _id: 'scan_schedule',
      enabled,
      interval_minutes: intervalMinutes ?? 60,
      updated_at: new Date(),
    };

    await db.collection('settings').updateOne(
      { _id: 'scan_schedule' },
      { $set: update, $setOnInsert: { created_at: new Date() } },
      { upsert: true }
    );

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
