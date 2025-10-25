/**
 * Device Management Routes
 * Handle device registration, status, and management
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();
const { getUserDevices } = require('../socket/socketHandler');

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Access token required'
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        error: 'Invalid or expired token'
      });
    }
    req.user = user;
    next();
  });
};

// In-memory device registry (replace with database)
const deviceRegistry = new Map();

/**
 * POST /api/devices/register
 * Register a new device
 */
router.post('/register', authenticateToken, (req, res) => {
  try {
    const { deviceId, deviceType, deviceName, os, version } = req.body;
    const userId = req.user.id;

    if (!deviceId || !deviceType) {
      return res.status(400).json({
        success: false,
        error: 'Device ID and type required'
      });
    }

    const deviceKey = `${userId}:${deviceId}`;
    const device = {
      userId,
      deviceId,
      deviceType, // 'desktop' or 'mobile'
      deviceName: deviceName || `${deviceType} Device`,
      os: os || 'unknown',
      version: version || '1.0.0',
      registeredAt: new Date(),
      lastSeen: new Date()
    };

    deviceRegistry.set(deviceKey, device);

    res.json({
      success: true,
      message: 'Device registered successfully',
      device
    });

  } catch (error) {
    console.error('Device registration error:', error);
    res.status(500).json({
      success: false,
      error: 'Registration failed'
    });
  }
});

/**
 * GET /api/devices
 * Get all devices for current user
 */
router.get('/', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;

    // Get registered devices
    const userDevices = Array.from(deviceRegistry.values())
      .filter(device => device.userId === userId);

    // Get currently connected devices
    const activeDevices = getUserDevices(userId);

    // Merge data
    const devices = userDevices.map(device => ({
      ...device,
      online: activeDevices.some(ad => ad.deviceId === device.deviceId)
    }));

    res.json({
      success: true,
      devices,
      total: devices.length,
      online: devices.filter(d => d.online).length
    });

  } catch (error) {
    console.error('Get devices error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch devices'
    });
  }
});

/**
 * DELETE /api/devices/:deviceId
 * Unregister a device
 */
router.delete('/:deviceId', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const { deviceId } = req.params;

    const deviceKey = `${userId}:${deviceId}`;

    if (!deviceRegistry.has(deviceKey)) {
      return res.status(404).json({
        success: false,
        error: 'Device not found'
      });
    }

    deviceRegistry.delete(deviceKey);

    res.json({
      success: true,
      message: 'Device unregistered successfully'
    });

  } catch (error) {
    console.error('Device deletion error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete device'
    });
  }
});

/**
 * PUT /api/devices/:deviceId/heartbeat
 * Update device last seen timestamp
 */
router.put('/:deviceId/heartbeat', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const { deviceId } = req.params;

    const deviceKey = `${userId}:${deviceId}`;
    const device = deviceRegistry.get(deviceKey);

    if (!device) {
      return res.status(404).json({
        success: false,
        error: 'Device not found'
      });
    }

    device.lastSeen = new Date();
    deviceRegistry.set(deviceKey, device);

    res.json({
      success: true,
      message: 'Heartbeat received'
    });

  } catch (error) {
    console.error('Heartbeat error:', error);
    res.status(500).json({
      success: false,
      error: 'Heartbeat failed'
    });
  }
});

module.exports = router;
