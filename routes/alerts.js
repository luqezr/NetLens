const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');

// Alert Schema
const AlertSchema = new mongoose.Schema({
  device_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Device' },
  alert_type: String,
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'] },
  title: String,
  message: String,
  created_at: { type: Date, default: Date.now },
  acknowledged: { type: Boolean, default: false },
  acknowledged_by: String,
  acknowledged_at: Date
});

const Alert = mongoose.model('Alert', AlertSchema);

// GET all alerts
router.get('/', async (req, res) => {
  try {
    const { acknowledged, severity } = req.query;
    
    let query = {};
    if (acknowledged !== undefined) {
      query.acknowledged = acknowledged === 'true';
    }
    if (severity) {
      query.severity = severity;
    }
    
    const alerts = await Alert.find(query)
      .populate('device_id', 'ip_address hostname device_type')
      .sort({ created_at: -1 })
      .limit(100);
    
    res.json({
      success: true,
      count: alerts.length,
      data: alerts
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST acknowledge alert
router.post('/:id/acknowledge', async (req, res) => {
  try {
    const { acknowledged_by } = req.body;
    
    const alert = await Alert.findByIdAndUpdate(
      req.params.id,
      {
        acknowledged: true,
        acknowledged_by: acknowledged_by || 'admin',
        acknowledged_at: new Date()
      },
      { new: true }
    );
    
    if (!alert) {
      return res.status(404).json({ success: false, error: 'Alert not found' });
    }
    
    res.json({ success: true, data: alert });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// DELETE alert
router.delete('/:id', async (req, res) => {
  try {
    const alert = await Alert.findByIdAndDelete(req.params.id);
    
    if (!alert) {
      return res.status(404).json({ success: false, error: 'Alert not found' });
    }
    
    res.json({ success: true, message: 'Alert deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
