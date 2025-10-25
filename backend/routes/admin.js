const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const authService = require('../auth-service');

const router = express.Router();
const db = new sqlite3.Database('./data/auth.db');

// Middleware to check if user is admin
const isAdmin = (req, res, next) => {
  const userId = req.user.id;
  
  db.get('SELECT role FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database error' });
    }
    
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }
    
    next();
  });
};

// Get all users (admin only)
router.get('/users', isAdmin, (req, res) => {
  const query = `
    SELECT 
      u.id,
      u.email,
      u.name,
      u.tier,
      u.role,
      u.status,
      u.created_at,
      u.last_login,
      COUNT(DISTINCT s.id) as scans_count,
      COALESCE(SUM(CASE WHEN sr.threat_detected = 1 THEN 1 ELSE 0 END), 0) as threats_found
    FROM users u
    LEFT JOIN scans s ON u.id = s.user_id
    LEFT JOIN scan_results sr ON s.id = sr.scan_id
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `;
  
  db.all(query, [], (err, users) => {
    if (err) {
      console.error('Failed to fetch users:', err);
      return res.status(500).json({ success: false, error: 'Database error' });
    }
    
    res.json({ success: true, users });
  });
});

// Update user role (admin only)
router.post('/update-role', isAdmin, (req, res) => {
  const { userId, role } = req.body;
  
  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ success: false, error: 'Invalid role' });
  }
  
  db.run(
    'UPDATE users SET role = ? WHERE id = ?',
    [role, userId],
    function(err) {
      if (err) {
        console.error('Failed to update role:', err);
        return res.status(500).json({ success: false, error: 'Database error' });
      }
      
      // Log audit entry
      logAuditEntry(req.user.id, 'ROLE_UPDATED', `Changed user ${userId} role to ${role}`);
      
      res.json({ success: true, message: 'Role updated successfully' });
    }
  );
});

// Update user tier (admin only)
router.post('/update-tier', isAdmin, (req, res) => {
  const { userId, tier } = req.body;
  
  if (!['free', 'premium'].includes(tier)) {
    return res.status(400).json({ success: false, error: 'Invalid tier' });
  }
  
  db.run(
    'UPDATE users SET tier = ? WHERE id = ?',
    [tier, userId],
    function(err) {
      if (err) {
        console.error('Failed to update tier:', err);
        return res.status(500).json({ success: false, error: 'Database error' });
      }
      
      // Log audit entry
      logAuditEntry(req.user.id, 'TIER_UPDATED', `Changed user ${userId} tier to ${tier}`);
      
      res.json({ success: true, message: 'Tier updated successfully' });
    }
  );
});

// Suspend user (admin only)
router.post('/suspend-user', isAdmin, (req, res) => {
  const { userId } = req.body;
  
  db.run(
    'UPDATE users SET status = ? WHERE id = ?',
    ['suspended', userId],
    function(err) {
      if (err) {
        console.error('Failed to suspend user:', err);
        return res.status(500).json({ success: false, error: 'Database error' });
      }
      
      // Log audit entry
      logAuditEntry(req.user.id, 'USER_SUSPENDED', `Suspended user ${userId}`);
      
      res.json({ success: true, message: 'User suspended successfully' });
    }
  );
});

// Activate user (admin only)
router.post('/activate-user', isAdmin, (req, res) => {
  const { userId } = req.body;
  
  db.run(
    'UPDATE users SET status = ? WHERE id = ?',
    ['active', userId],
    function(err) {
      if (err) {
        console.error('Failed to activate user:', err);
        return res.status(500).json({ success: false, error: 'Database error' });
      }
      
      // Log audit entry
      logAuditEntry(req.user.id, 'USER_ACTIVATED', `Activated user ${userId}`);
      
      res.json({ success: true, message: 'User activated successfully' });
    }
  );
});

// Delete user (admin only)
router.delete('/users/:userId', isAdmin, (req, res) => {
  const { userId } = req.params;
  
  // Don't allow deleting yourself
  if (parseInt(userId) === req.user.id) {
    return res.status(400).json({ success: false, error: 'Cannot delete your own account' });
  }
  
  db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
    if (err) {
      console.error('Failed to delete user:', err);
      return res.status(500).json({ success: false, error: 'Database error' });
    }
    
    // Log audit entry
    logAuditEntry(req.user.id, 'USER_DELETED', `Deleted user ${userId}`);
    
    res.json({ success: true, message: 'User deleted successfully' });
  });
});

// Reset all users' 2FA (admin only)
router.post('/reset-2fa', isAdmin, (req, res) => {
  // Reset in-memory auth service data
  const result = authService.resetAll2FA();
  
  // Also update database if 2FA columns exist
  db.run(
    `UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE 1=1`,
    [],
    function(err) {
      // Ignore error if columns don't exist - they may be in-memory only
      if (err && !err.message.includes('no such column')) {
        console.error('Database 2FA reset error:', err);
      }
    }
  );
  
  // Log audit entry
  logAuditEntry(req.user.id, '2FA_RESET_ALL', `Reset 2FA for all users - ${result.count} users affected`);
  
  res.json({ 
    success: true, 
    message: result.message,
    count: result.count,
    note: 'All users can now re-enable 2FA in their settings.'
  });
});

// Reset specific user's 2FA (admin only)
router.post('/reset-2fa/:userId', isAdmin, (req, res) => {
  const { userId } = req.params;
  
  // First get user email from database
  db.get('SELECT email FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      console.error('Failed to find user:', err);
      return res.status(500).json({ success: false, error: 'Database error' });
    }
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    // Reset in-memory 2FA
    const result = authService.reset2FAForUser(user.email);
    
    // Also update database if 2FA columns exist
    db.run(
      `UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?`,
      [userId],
      function(err) {
        if (err && !err.message.includes('no such column')) {
          console.error('Database 2FA reset error:', err);
        }
      }
    );
    
    // Log audit entry
    logAuditEntry(req.user.id, '2FA_RESET_USER', `Reset 2FA for user ${userId} (${user.email})`);
    
    res.json({ 
      success: true, 
      message: result.message,
      note: 'User can re-enable 2FA in settings if needed.'
    });
  });
});

// Get audit logs (admin only)
router.get('/audit-logs', isAdmin, (req, res) => {
  const query = `
    SELECT 
      al.id,
      u.email as user_email,
      al.action,
      al.details,
      al.timestamp,
      al.status
    FROM audit_logs al
    LEFT JOIN users u ON al.user_id = u.id
    ORDER BY al.timestamp DESC
    LIMIT 100
  `;
  
  db.all(query, [], (err, logs) => {
    if (err) {
      console.error('Failed to fetch audit logs:', err);
      return res.status(500).json({ success: false, error: 'Database error' });
    }
    
    res.json({ success: true, logs });
  });
});

// Helper function to log audit entries
function logAuditEntry(userId, action, details, status = 'success') {
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
  
  db.run(
    'INSERT INTO audit_logs (user_id, action, details, timestamp, status) VALUES (?, ?, ?, ?, ?)',
    [userId, action, details, timestamp, status],
    (err) => {
      if (err) {
        console.error('Failed to log audit entry:', err);
      }
    }
  );
}

module.exports = router;
