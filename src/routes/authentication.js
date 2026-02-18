/**
 * API Routes for Authentication Hardening
 */

import express from 'express';
import AuthenticationHardeningService from '../services/AuthenticationHardeningService.js';

const router = express.Router();

// Get authentication statistics
router.get('/hardening/stats', async (req, res) => {
  try {
    const stats = AuthenticationHardeningService.getStatistics();
    
    // Get active sessions (without sensitive data)
    const sessions = Array.from(AuthenticationHardeningService.activeSessions.values()).map(session => ({
      id: session.id,
      userId: session.userId,
      ipAddress: session.ipAddress,
      location: session.location,
      fingerprint: session.fingerprint,
      riskScore: session.riskScore,
      lastActivity: session.lastActivity,
      createdAt: session.createdAt
    }));
    
    // Get device fingerprints
    const fingerprints = Array.from(AuthenticationHardeningService.deviceFingerprints.values()).slice(0, 20);
    
    // Get anomalous logins (last 24 hours)
    const anomalousLogins = [];
    
    // Get locked accounts
    const lockedAccounts = [];
    for (const [userId, attempts] of AuthenticationHardeningService.loginAttempts) {
      const recentAttempts = attempts.filter(
        a => Date.now() - a.timestamp < AuthenticationHardeningService.lockoutDuration
      );
      
      if (recentAttempts.length >= AuthenticationHardeningService.maxLoginAttempts) {
        lockedAccounts.push({
          userId,
          attempts: recentAttempts.length,
          lockoutEnd: recentAttempts[0].timestamp + AuthenticationHardeningService.lockoutDuration
        });
      }
    }
    
    res.json({
      success: true,
      stats,
      sessions,
      fingerprints,
      anomalousLogins,
      lockedAccounts
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Generate device fingerprint
router.post('/fingerprint', async (req, res) => {
  try {
    const fingerprint = await AuthenticationHardeningService.generateDeviceFingerprint(req.body);
    
    res.json({
      success: true,
      fingerprint: {
        hash: fingerprint.hash,
        timestamp: fingerprint.timestamp
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Verify device fingerprint
router.post('/fingerprint/verify', async (req, res) => {
  try {
    const { fingerprintHash, context } = req.body;
    
    const verification = AuthenticationHardeningService.verifyDeviceFingerprint(
      fingerprintHash,
      context
    );
    
    res.json({
      success: true,
      verification
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Analyze behavioral biometrics
router.post('/behavior/analyze', async (req, res) => {
  try {
    const { userId, behavior } = req.body;
    
    const analysis = await AuthenticationHardeningService.analyzeBehavioralBiometrics(
      userId,
      behavior
    );
    
    res.json({
      success: true,
      analysis
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Detect anomalous location
router.post('/location/analyze', async (req, res) => {
  try {
    const { userId, location } = req.body;
    
    const analysis = await AuthenticationHardeningService.detectAnomalousLocation(
      userId,
      location
    );
    
    res.json({
      success: true,
      analysis
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Create session (login)
router.post('/session', async (req, res) => {
  try {
    const { userId, context } = req.body;
    
    const result = await AuthenticationHardeningService.createSession(userId, context);
    
    res.json({
      success: result.success,
      ...result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Validate session
router.post('/session/validate', async (req, res) => {
  try {
    const { sessionId, context } = req.body;
    
    const hijackCheck = await AuthenticationHardeningService.preventSessionHijacking(
      sessionId,
      context
    );
    
    res.json({
      success: !hijackCheck.hijacked,
      hijackCheck
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Terminate session
router.delete('/session/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { reason } = req.body;
    
    const terminated = AuthenticationHardeningService.terminateSession(sessionId, reason);
    
    res.json({
      success: terminated
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Record failed login
router.post('/login/failed', async (req, res) => {
  try {
    const { userId, context } = req.body;
    
    AuthenticationHardeningService.recordFailedLogin(userId, context);
    
    res.json({
      success: true
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Unlock account
router.post('/unlock/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Clear login attempts
    AuthenticationHardeningService.loginAttempts.delete(userId);
    
    res.json({
      success: true
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

export default router;
