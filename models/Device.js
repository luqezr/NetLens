const mongoose = require('mongoose');

const DeviceSchema = new mongoose.Schema({
  ip_address: { type: String, required: true, unique: true },
  mac_address: String,
  previous_ips: [String],
  hostname: String,
  hostnames: [String],
  vendor: String,
  device_type: String,
  // Scanner may provide rich OS info (nmap osmatch/osclass, etc). Keep it flexible.
  os: mongoose.Schema.Types.Mixed,
  // Some paths use connection_method; others use connection object.
  connection_method: String,
  connection: mongoose.Schema.Types.Mixed,
  interfaces: [{
    name: String,
    type: String,
    ip: String,
    mac: String,
    speed_mbps: Number,
    status: String
  }],
  // Scanner emits a richer service object (protocol/product/cpe/scripts/etc).
  services: [mongoose.Schema.Types.Mixed],
  status: { type: String, default: 'online' },
  first_seen: { type: Date, default: Date.now },
  last_seen: { type: Date, default: Date.now },
  last_scan: { type: Date, default: Date.now },
  // Preferred naming for UI/API consumers (kept alongside last_seen/last_scan for back-compat)
  last_seen_on: { type: Date },
  last_scan_on: { type: Date },
  uptime_seconds: Number,
  response_time_ms: Number,
  // Keep security flexible (open_ports_count + cves + cve_count, etc)
  security: mongoose.Schema.Types.Mixed,
  metadata: {
    model: String,
    serial_number: String,
    location: String,
    tags: [String]
  }
}, { timestamps: true, strict: false });

module.exports = mongoose.model('Device', DeviceSchema);