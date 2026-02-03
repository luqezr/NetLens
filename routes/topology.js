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
    
    // Get all devices
    const devices = await Device.find({ status: 'online' })
      .select('ip_address hostname device_type vendor connection');
    
    // Get topology connections
    const connections = await Topology.find()
      .populate('source_device_id', 'ip_address hostname device_type')
      .populate('target_device_id', 'ip_address hostname device_type');
    
    // Format for network visualization
    const nodes = devices.map(device => ({
      id: device._id.toString(),
      ip: device.ip_address,
      label: device.hostname || device.ip_address,
      type: device.device_type,
      vendor: device.vendor,
      connection: device.connection?.type || 'unknown'
    }));
    
    const edges = connections.map(conn => ({
      source: conn.source_device_id?._id.toString(),
      target: conn.target_device_id?._id.toString(),
      type: conn.connection_type
    })).filter(edge => edge.source && edge.target);
    
    res.json({
      success: true,
      data: {
        nodes,
        edges
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
