const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');

// Topology Schema
const TopologySchema = new mongoose.Schema({
  source_device_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Device' },
  target_device_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Device' },
  connection_type: String,
  details: mongoose.Schema.Types.Mixed,
  discovered_at: { type: Date, default: Date.now },
  last_verified: { type: Date, default: Date.now }
});

const Topology = mongoose.model('Topology', TopologySchema);

// GET network topology
router.get('/', async (req, res) => {
  try {
    const Device = require('../models/Device');

    function ipv4Prefix24(ip) {
      if (!ip || typeof ip !== 'string') return null;
      const parts = ip.trim().split('.');
      if (parts.length !== 4) return null;
      if (!parts.every((p) => p !== '' && Number.isFinite(Number(p)) && Number(p) >= 0 && Number(p) <= 255)) return null;
      return `${parts[0]}.${parts[1]}.${parts[2]}`;
    }

    function pickLikelyRouter(devices) {
      if (!Array.isArray(devices) || devices.length === 0) return { router: null, prefix: null };

      const counts = new Map();
      for (const d of devices) {
        const prefix = ipv4Prefix24(d.ip_address);
        if (!prefix) continue;
        counts.set(prefix, (counts.get(prefix) || 0) + 1);
      }
      let bestPrefix = null;
      let bestCount = -1;
      for (const [prefix, c] of counts.entries()) {
        if (c > bestCount) {
          bestCount = c;
          bestPrefix = prefix;
        }
      }

      // 1) Prefer x.x.x.1 on the dominant /24.
      if (bestPrefix) {
        const candidateIp = `${bestPrefix}.1`;
        const byIp = devices.find((d) => d.ip_address === candidateIp);
        if (byIp) return { router: byIp, prefix: bestPrefix };
      }

      // 2) Device explicitly typed as router/gateway.
      const byType = devices.find((d) => String(d.device_type || '').toLowerCase().includes('router'))
        || devices.find((d) => String(d.device_type || '').toLowerCase().includes('gateway'));
      if (byType) return { router: byType, prefix: ipv4Prefix24(byType.ip_address) };

      // 3) Heuristics: hostname hints.
      const byHostname = devices.find((d) => String(d.hostname || '').toLowerCase().includes('router'))
        || devices.find((d) => String(d.hostname || '').toLowerCase().includes('gateway'));
      if (byHostname) return { router: byHostname, prefix: ipv4Prefix24(byHostname.ip_address) };

      // 4) Fallback to lowest IPv4 in dominant /24.
      const pool = bestPrefix ? devices.filter((d) => ipv4Prefix24(d.ip_address) === bestPrefix) : devices;
      const sorted = [...pool].sort((a, b) => {
        const ai = (a.ip_address || '').split('.').map((n) => Number(n));
        const bi = (b.ip_address || '').split('.').map((n) => Number(n));
        for (let i = 0; i < 4; i += 1) {
          const av = Number.isFinite(ai[i]) ? ai[i] : 999;
          const bv = Number.isFinite(bi[i]) ? bi[i] : 999;
          if (av !== bv) return av - bv;
        }
        return 0;
      });
      return { router: sorted[0] || null, prefix: bestPrefix };
    }
    
    // Get all devices
    const devices = await Device.find({ status: 'online' })
      .select('ip_address hostname device_type vendor connection connection_method');
    
    // Get topology connections
    const connections = await Topology.find()
      .populate('source_device_id', 'ip_address hostname device_type')
      .populate('target_device_id', 'ip_address hostname device_type');
    
    // Format for network visualization
    const { router, prefix } = pickLikelyRouter(devices);
    const routerId = router?._id ? router._id.toString() : null;

    const switchId = routerId ? `switch-${routerId}` : (prefix ? `switch-${prefix}.0/24` : 'switch');
    const switchNode = {
      id: switchId,
      ip: prefix ? `${prefix}.0/24` : '—',
      label: 'Switch',
      type: 'switch',
      vendor: '',
      connection: 'wired',
    };

    const nodes = [
      switchNode,
      ...devices.map(device => ({
        id: device._id.toString(),
        ip: device.ip_address,
        label: device.hostname || device.ip_address,
        type: (routerId && device._id.toString() === routerId) ? 'router' : (device.device_type || 'unknown'),
        vendor: device.vendor,
        connection: device.connection_method || (typeof device.connection === 'string' ? device.connection : (device.connection?.type || 'unknown')),
      }))
    ];
    
    const edges = connections.map(conn => ({
      source: conn.source_device_id?._id.toString(),
      target: conn.target_device_id?._id.toString(),
      type: conn.connection_type
    })).filter(edge => edge.source && edge.target);

    // If there are no stored topology edges, infer a basic star topology:
    // router -> switch -> devices.
    const inferredEdges = [];
    if (routerId) {
      inferredEdges.push({ source: routerId, target: switchId, type: 'uplink' });
    } else {
      // Create a virtual router when none is detected.
      const virtualRouterId = prefix ? `router-${prefix}.1` : 'router';
      nodes.unshift({
        id: virtualRouterId,
        ip: prefix ? `${prefix}.1` : '—',
        label: 'Router',
        type: 'router',
        vendor: '',
        connection: 'unknown',
      });
      inferredEdges.push({ source: virtualRouterId, target: switchId, type: 'uplink' });
    }

    for (const d of devices) {
      const id = d._id.toString();
      if (routerId && id === routerId) continue;
      inferredEdges.push({ source: switchId, target: id, type: 'lan' });
    }

    // Merge + de-dupe
    const merged = [...edges, ...inferredEdges];
    const seen = new Set();
    const deduped = [];
    for (const e of merged) {
      if (!e.source || !e.target) continue;
      const key = `${e.source}=>${e.target}:${e.type || ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(e);
    }
    
    res.json({
      success: true,
      data: {
        nodes,
        edges: deduped
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
