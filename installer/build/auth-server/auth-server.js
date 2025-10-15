const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.AUTH_PORT || 8081;
const JWT_SECRET = process.env.JWT_SECRET || 'nebula-shield-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// Database setup
const dbPath = path.join(__dirname, '..', 'data', 'auth.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Failed to connect to auth database:', err);
  } else {
    console.log('✅ Auth database connected:', dbPath);
    initializeDatabase();
  }
});

// Initialize database tables
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME
      )
    `, (err) => {
      if (err) console.error('Error creating users table:', err);
      else console.log('✅ Users table ready');
    });

    // Subscriptions table
    db.run(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        tier TEXT NOT NULL DEFAULT 'free',
        status TEXT NOT NULL DEFAULT 'active',
        started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `, (err) => {
      if (err) console.error('Error creating subscriptions table:', err);
      else console.log('✅ Subscriptions table ready');
    });

    // User settings table
    db.run(`
      CREATE TABLE IF NOT EXISTS user_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        settings_json TEXT NOT NULL DEFAULT '{}',
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `, (err) => {
      if (err) console.error('Error creating user_settings table:', err);
      else console.log('✅ User settings table ready');
    });
  });
}

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ====== AUTHENTICATION ROUTES ======

// Register new user
app.post('/api/auth/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('fullName').trim().isLength({ min: 2 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const { email, password, fullName } = req.body;

  try {
    // Check if user exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (row) {
        return res.status(400).json({ success: false, message: 'Email already registered' });
      }

      // Hash password
      const passwordHash = await bcrypt.hash(password, 10);

      // Create user
      db.run(
        'INSERT INTO users (email, password_hash, full_name) VALUES (?, ?, ?)',
        [email, passwordHash, fullName],
        function(err) {
          if (err) {
            return res.status(500).json({ success: false, message: 'Failed to create user' });
          }

          const userId = this.lastID;

          // Create free subscription
          db.run(
            'INSERT INTO subscriptions (user_id, tier, status) VALUES (?, ?, ?)',
            [userId, 'free', 'active'],
            (err) => {
              if (err) {
                console.error('Failed to create subscription:', err);
              }

              // Generate token
              const token = jwt.sign({ userId, email, tier: 'free' }, JWT_SECRET, { expiresIn: '7d' });

              res.status(201).json({
                success: true,
                message: 'Account created successfully',
                token,
                user: {
                  id: userId,
                  email,
                  fullName,
                  tier: 'free'
                }
              });
            }
          );
        }
      );
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const { email, password } = req.body;

  db.get(
    'SELECT u.*, s.tier FROM users u LEFT JOIN subscriptions s ON u.id = s.user_id WHERE u.email = ? AND s.status = "active"',
    [email],
    async (err, user) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (!user) {
        return res.status(401).json({ success: false, message: 'Invalid email or password' });
      }

      // Verify password
      const validPassword = await bcrypt.compare(password, user.password_hash);
      if (!validPassword) {
        return res.status(401).json({ success: false, message: 'Invalid email or password' });
      }

      // Update last login
      db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

      // Generate token
      const token = jwt.sign(
        { userId: user.id, email: user.email, tier: user.tier || 'free' },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        success: true,
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          email: user.email,
          fullName: user.full_name,
          tier: user.tier || 'free'
        }
      });
    }
  );
});

// Verify token and get user info
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  db.get(
    'SELECT u.id, u.email, u.full_name, s.tier FROM users u LEFT JOIN subscriptions s ON u.id = s.user_id WHERE u.id = ? AND s.status = "active"',
    [req.user.userId],
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }

      res.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          fullName: user.full_name,
          tier: user.tier || 'free'
        }
      });
    }
  );
});

// ====== SUBSCRIPTION ROUTES ======

// Get subscription info
app.get('/api/subscription', authenticateToken, (req, res) => {
  db.get(
    'SELECT tier, status, started_at, expires_at FROM subscriptions WHERE user_id = ? AND status = "active"',
    [req.user.userId],
    (err, subscription) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      res.json({
        success: true,
        subscription: subscription || { tier: 'free', status: 'active' }
      });
    }
  );
});

// Upgrade to premium
app.post('/api/subscription/upgrade', authenticateToken, (req, res) => {
  const expiresAt = new Date();
  expiresAt.setFullYear(expiresAt.getFullYear() + 1); // 1 year subscription

  db.run(
    'UPDATE subscriptions SET tier = ?, expires_at = ? WHERE user_id = ? AND status = "active"',
    ['premium', expiresAt.toISOString(), req.user.userId],
    function(err) {
      if (err) {
        return res.status(500).json({ success: false, message: 'Failed to upgrade subscription' });
      }

      res.json({
        success: true,
        message: 'Upgraded to Premium successfully!',
        subscription: {
          tier: 'premium',
          expiresAt: expiresAt.toISOString()
        }
      });
    }
  );
});

// Check if feature is available for user's tier
app.post('/api/subscription/check-feature', authenticateToken, (req, res) => {
  const { feature } = req.body;

  const premiumFeatures = [
    'scheduled-scans',
    'advanced-reports',
    'custom-scan-paths',
    'priority-support',
    'advanced-threats'
  ];

  db.get(
    'SELECT tier FROM subscriptions WHERE user_id = ? AND status = "active"',
    [req.user.userId],
    (err, subscription) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      const tier = subscription?.tier || 'free';
      const hasAccess = tier === 'premium' || !premiumFeatures.includes(feature);

      res.json({
        success: true,
        hasAccess,
        tier,
        requiresUpgrade: !hasAccess
      });
    }
  );
});

// ====== USER SETTINGS ROUTES ======

// Get user settings
app.get('/api/settings', authenticateToken, (req, res) => {
  db.get(
    'SELECT settings_json FROM user_settings WHERE user_id = ?',
    [req.user.userId],
    (err, row) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      const settings = row ? JSON.parse(row.settings_json) : {};
      res.json({
        success: true,
        settings
      });
    }
  );
});

// Save user settings
app.post('/api/settings', authenticateToken, (req, res) => {
  const { settings } = req.body;

  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ success: false, message: 'Invalid settings data' });
  }

  const settingsJson = JSON.stringify(settings);

  db.run(
    `INSERT INTO user_settings (user_id, settings_json, updated_at)
     VALUES (?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(user_id) DO UPDATE SET 
       settings_json = excluded.settings_json,
       updated_at = CURRENT_TIMESTAMP`,
    [req.user.userId, settingsJson],
    function(err) {
      if (err) {
        return res.status(500).json({ success: false, message: 'Failed to save settings' });
      }

      res.json({
        success: true,
        message: 'Settings saved successfully'
      });
    }
  );
});

// ====== SERVER ======

app.listen(PORT, () => {
  console.log(`\n🔐 Nebula Shield Auth Server`);
  console.log(`📡 Listening on port ${PORT}`);
  console.log(`🔑 JWT authentication enabled\n`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down auth server...');
  db.close((err) => {
    if (err) console.error('Error closing database:', err);
    else console.log('✅ Database closed');
    process.exit(0);
  });
});
