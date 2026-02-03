const express = require('express');
const router = express.Router();
const Device = require('../models/Device');

// GET all devices
router.get('/', async (req, res) => {
  try {
    const { status, device_type, search } = req.query;
    
    let query = {};
    
    if (status) query.status = status;
    if (device_type) query.device_type = device_type;
    if (search) {
      query.$or = [
        { ip_address: { $regex: search, $options: 'i' } },
        { hostname: { $regex: search, $options: 'i' } },
        { vendor: { $regex: search, $options: 'i' } }
      ];
    }
    
    const devices = await Device.find(query)
      .sort({ last_seen: -1 })
      .limit(1000);
    
    res.json({
      success: true,
      count: devices.length,
      data: devices
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET single device by IP
router.get('/:ip', async (req, res) => {
  try {
    const device = await Device.findOne({ ip_address: req.params.ip });
    
    if (!device) {
      return res.status(404).json({ success: false, error: 'Device not found' });
    }
    
    res.json({ success: true, data: device });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// UPDATE device metadata
router.patch('/:ip', async (req, res) => {
  try {
    const { metadata } = req.body;
    
    const device = await Device.findOneAndUpdate(
      { ip_address: req.params.ip },
      { $set: { metadata } },
      { new: true }
    );
    
    if (!device) {
      return res.status(404).json({ success: false, error: 'Device not found' });
    }
    
    res.json({ success: true, data: device });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// DELETE device
router.delete('/:ip', async (req, res) => {
  try {
    const device = await Device.findOneAndDelete({ ip_address: req.params.ip });
    
    if (!device) {
      return res.status(404).json({ success: false, error: 'Device not found' });
    }
    
    res.json({ success: true, message: 'Device deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;