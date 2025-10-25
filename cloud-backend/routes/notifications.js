/**
 * Push Notification Routes
 * Handle FCM/APNs push notifications
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

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

// Store FCM tokens (replace with database)
const fcmTokens = new Map(); // userId -> [tokens]

/**
 * POST /api/notifications/register-token
 * Register FCM/APNs token for push notifications
 */
router.post('/register-token', authenticateToken, (req, res) => {
  try {
    const { token: fcmToken, platform } = req.body;
    const userId = req.user.id;

    if (!fcmToken) {
      return res.status(400).json({
        success: false,
        error: 'FCM token required'
      });
    }

    if (!fcmTokens.has(userId)) {
      fcmTokens.set(userId, []);
    }

    const userTokens = fcmTokens.get(userId);
    if (!userTokens.includes(fcmToken)) {
      userTokens.push(fcmToken);
    }

    console.log(`📱 Registered push token for user ${userId} (${platform})`);

    res.json({
      success: true,
      message: 'Push token registered successfully'
    });

  } catch (error) {
    console.error('Token registration error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to register token'
    });
  }
});

/**
 * POST /api/notifications/send
 * Send push notification (internal use)
 */
router.post('/send', authenticateToken, async (req, res) => {
  try {
    const { userId, title, body, data } = req.body;

    // Get user's FCM tokens
    const tokens = fcmTokens.get(userId) || [];

    if (tokens.length === 0) {
      return res.json({
        success: true,
        message: 'No devices to notify',
        sent: 0
      });
    }

    // TODO: Implement actual Firebase Cloud Messaging
    // For now, just log
    console.log(`📨 Sending push notification to user ${userId}:`, { title, body });

    /*
    // Example Firebase implementation:
    const admin = require('firebase-admin');
    const message = {
      notification: { title, body },
      data: data || {},
      tokens
    };
    const response = await admin.messaging().sendMulticast(message);
    */

    res.json({
      success: true,
      message: 'Notifications sent',
      sent: tokens.length
    });

  } catch (error) {
    console.error('Send notification error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send notification'
    });
  }
});

/**
 * DELETE /api/notifications/token
 * Unregister FCM token
 */
router.delete('/token', authenticateToken, (req, res) => {
  try {
    const { token: fcmToken } = req.body;
    const userId = req.user.id;

    if (!fcmToken) {
      return res.status(400).json({
        success: false,
        error: 'FCM token required'
      });
    }

    if (fcmTokens.has(userId)) {
      const userTokens = fcmTokens.get(userId);
      const index = userTokens.indexOf(fcmToken);
      if (index > -1) {
        userTokens.splice(index, 1);
      }
    }

    res.json({
      success: true,
      message: 'Token unregistered'
    });

  } catch (error) {
    console.error('Token unregister error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to unregister token'
    });
  }
});

module.exports = router;
