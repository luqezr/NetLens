const mongoose = require('mongoose');

const DeviceSchema = new mongoose.Schema({
  ip_address: { type: String, required: true, unique: true },
  mac_address: String,
  hostname: String,
  vendor: String,
  device_type: String,
  os: {
    type: String,
    version: String,
    confidence: Number
  },
  connection: {
    type: String,
    ssid: String,
    signal_strength: Number,
    access_point: String
  },
  interfaces: [{
    name: String,
    type: String,
    ip: String,
    mac: String,
    speed_mbps: Number,
    status: String
  }],
  services: [{
    port: Number,
    protocol: String,
    name: String,
    version: String,
    banner: String
  }],
  status: { type: String, default: 'online' },
  first_seen: { type: Date, default: Date.now },
  last_seen: { type: Date, default: Date.now },
  last_scan: { type: Date, default: Date.now },
  // Preferred naming for UI/API consumers (kept alongside last_seen/last_scan for back-compat)
  last_seen_on: { type: Date },
  last_scan_on: { type: Date },
  uptime_seconds: Number,
  response_time_ms: Number,
  security: {
    open_ports_count: Number,
    vulnerabilities: [String],
    risk_level: String
  },
  metadata: {
    model: String,
    serial_number: String,
    location: String,
    tags: [String]
  }
}, { timestamps: true });

module.exports = mongoose.model('Device', DeviceSchema);