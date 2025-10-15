/**
 * License Management API Routes
 * Express router for license operations
 */

const express = require('express');
const router = express.Router();
const licenseGenerator = require('./license-generator');

// Middleware to log requests
router.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  console.log(`[License API] ${req.method} ${req.path} from ${ip}`);
  next();
});

/**
 * POST /api/license/generate
 * Generate a new license key (admin only)
 */
router.post('/generate', async (req, res) => {
  try {
    const { tier, email, durationDays, orderId, paymentMethod, amount } = req.body;

    if (!tier || !email || !durationDays) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: tier, email, durationDays'
      });
    }

    const result = await licenseGenerator.generateLicenseKey(
      tier,
      email,
      parseInt(durationDays),
      orderId,
      paymentMethod,
      amount
    );

    res.json(result);
  } catch (error) {
    console.error('License generation error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate license key'
    });
  }
});

/**
 * POST /api/license/validate
 * Validate a license key
 */
router.post('/validate', async (req, res) => {
  try {
    const { licenseKey } = req.body;

    if (!licenseKey) {
      return res.status(400).json({
        success: false,
        error: 'License key is required'
      });
    }

    const result = await licenseGenerator.validateLicenseKey(licenseKey);
    res.json({ success: true, ...result });
  } catch (error) {
    console.error('License validation error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to validate license key'
    });
  }
});

/**
 * POST /api/license/activate
 * Activate a license on a device
 */
router.post('/activate', async (req, res) => {
  try {
    const { licenseKey, deviceId, tosAccepted, deviceInfo } = req.body;

    if (!tosAccepted) {
      return res.status(400).json({
        success: false,
        error: 'Terms of Service must be accepted'
      });
    }

    if (!licenseKey || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'License key and device ID are required'
      });
    }

    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const enrichedDeviceInfo = {
      ...deviceInfo,
      ipAddress: ip,
      osInfo: deviceInfo?.osInfo || userAgent
    };

    const result = await licenseGenerator.activateLicense(
      licenseKey,
      deviceId,
      enrichedDeviceInfo
    );

    res.json(result);
  } catch (error) {
    console.error('License activation error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to activate license'
    });
  }
});

/**
 * POST /api/license/deactivate
 * Deactivate a license from a device
 */
router.post('/deactivate', async (req, res) => {
  try {
    const { licenseKey, deviceId } = req.body;

    if (!licenseKey || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'License key and device ID are required'
      });
    }

    const result = await licenseGenerator.deactivateLicense(licenseKey, deviceId);
    res.json(result);
  } catch (error) {
    console.error('License deactivation error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to deactivate license'
    });
  }
});

/**
 * GET /api/license/status
 * Get license status for a device
 */
router.get('/status', async (req, res) => {
  try {
    const { deviceId } = req.query;

    if (!deviceId) {
      return res.status(400).json({
        success: false,
        error: 'Device ID is required'
      });
    }

    const status = await licenseGenerator.getLicenseStatus(deviceId);
    res.json({ success: true, status });
  } catch (error) {
    console.error('License status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get license status'
    });
  }
});

/**
 * GET /api/license/activations/:licenseKey
 * Get all activations for a license key
 */
router.get('/activations/:licenseKey', async (req, res) => {
  try {
    const { licenseKey } = req.params;
    const activations = await licenseGenerator.getActivations(licenseKey);
    res.json({ success: true, activations });
  } catch (error) {
    console.error('Get activations error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get activations'
    });
  }
});

/**
 * POST /api/license/revoke
 * Revoke a license (admin only)
 */
router.post('/revoke', async (req, res) => {
  try {
    const { licenseKey, reason } = req.body;

    if (!licenseKey) {
      return res.status(400).json({
        success: false,
        error: 'License key is required'
      });
    }

    const result = await licenseGenerator.revokeLicense(
      licenseKey,
      reason || 'Revoked by administrator'
    );
    res.json(result);
  } catch (error) {
    console.error('License revocation error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to revoke license'
    });
  }
});

/**
 * POST /api/license/extend
 * Extend license expiration (admin only)
 */
router.post('/extend', async (req, res) => {
  try {
    const { licenseKey, additionalDays } = req.body;

    if (!licenseKey || !additionalDays) {
      return res.status(400).json({
        success: false,
        error: 'License key and additional days are required'
      });
    }

    const result = await licenseGenerator.extendLicense(
      licenseKey,
      parseInt(additionalDays)
    );
    res.json(result);
  } catch (error) {
    console.error('License extension error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to extend license'
    });
  }
});

/**
 * GET /api/license/history/:licenseKey
 * Get license history (admin only)
 */
router.get('/history/:licenseKey', async (req, res) => {
  try {
    const { licenseKey } = req.params;
    const history = await licenseGenerator.getHistory(licenseKey);
    res.json({ success: true, history });
  } catch (error) {
    console.error('Get history error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get license history'
    });
  }
});

/**
 * POST /api/license/tos-accept
 * Record ToS acceptance
 */
router.post('/tos-accept', async (req, res) => {
  try {
    const { email, version } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required'
      });
    }

    // In production, you'd update the user's ToS acceptance in the database
    res.json({
      success: true,
      message: 'Terms of Service accepted',
      acceptedAt: new Date().toISOString(),
      version: version || '1.0'
    });
  } catch (error) {
    console.error('ToS acceptance error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to record ToS acceptance'
    });
  }
});

module.exports = router;
