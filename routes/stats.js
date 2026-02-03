const express = require('express');
const router = express.Router();
const Device = require('../models/Device');

// GET dashboard statistics
router.get('/', async (req, res) => {
  try {
    // Total devices
    const total = await Device.countDocuments();
    
    // Online/Offline count
    const online = await Device.countDocuments({ status: 'online' });
    const offline = await Device.countDocuments({ status: 'offline' });
    
    // Devices by type
    const byType = await Device.aggregate([
      { $match: { status: 'online' } },
      { $group: { _id: '$device_type', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    // Devices by vendor
    const byVendor = await Device.aggregate([
      { $match: { status: 'online', vendor: { $ne: '' } } },
      { $group: { _id: '$vendor', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    // Recently seen devices
    const recentDevices = await Device.find()
      .sort({ last_seen: -1 })
      .limit(10)
      .select('ip_address hostname device_type last_seen status');
    
    res.json({
      success: true,
      data: {
        total_devices: total,
        online_devices: online,
        offline_devices: offline,
        by_type: byType,
        by_vendor: byVendor,
        recent_devices: recentDevices
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;