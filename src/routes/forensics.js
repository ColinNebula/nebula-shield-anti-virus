/**
 * API Routes for Forensics & Reporting
 */

import express from 'express';
import ForensicsService from '../services/ForensicsService.js';

const router = express.Router();

// Get forensics statistics
router.get('/stats', async (req, res) => {
  try {
    const stats = ForensicsService.getStatistics();
    
    // Get recent incidents
    const incidents = ForensicsService.attackLogs.slice(-50).reverse();
    
    // Get PCAP sessions
    const pcapSessions = [];
    
    res.json({
      success: true,
      stats,
      incidents,
      pcapSessions,
      activeCapture: ForensicsService.captureSession
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Start PCAP capture
router.post('/pcap/start', async (req, res) => {
  try {
    const { interface: iface, filter, maxSize, maxDuration } = req.body;
    
    const capture = await ForensicsService.startPCAPCapture({
      interface: iface,
      filter,
      maxSize,
      maxDuration
    });
    
    res.json({
      success: true,
      capture
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Stop PCAP capture
router.post('/pcap/stop', async (req, res) => {
  try {
    const session = ForensicsService.stopPCAPCapture();
    
    if (!session) {
      return res.status(404).json({
        success: false,
        error: 'No active capture session'
      });
    }
    
    res.json({
      success: true,
      session
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Analyze PCAP file
router.post('/pcap/analyze', async (req, res) => {
  try {
    const { pcapFile } = req.body;
    
    const analysis = await ForensicsService.analyzePCAP(pcapFile);
    
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

// Replay attack
router.post('/replay/:incidentId', async (req, res) => {
  try {
    const { incidentId } = req.params;
    
    const replay = await ForensicsService.replayAttack(incidentId);
    
    res.json({
      success: true,
      replay
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Generate compliance report
router.post('/compliance', async (req, res) => {
  try {
    const { standard, startDate, endDate } = req.body;
    
    const report = await ForensicsService.generateComplianceReport(standard, {
      startDate,
      endDate
    });
    
    res.json({
      success: true,
      report
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Export to SIEM
router.post('/siem/export', async (req, res) => {
  try {
    const { format, incidents } = req.body;
    
    const result = await ForensicsService.exportToSIEM(format, {
      incidents
    });
    
    res.json({
      success: true,
      ...result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Generate attack report
router.post('/report/:incidentId', async (req, res) => {
  try {
    const { incidentId } = req.params;
    
    const report = await ForensicsService.generateAttackReport(incidentId);
    
    res.json({
      success: true,
      report
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Log incident (for internal use)
router.post('/incident', async (req, res) => {
  try {
    const incident = ForensicsService.logIncident(req.body);
    
    res.json({
      success: true,
      incident
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

export default router;
