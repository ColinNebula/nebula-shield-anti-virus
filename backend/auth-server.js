const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
require('dotenv').config();

// Payment integrations
const { createStripeCheckoutSession, verifyStripePayment, handleStripeWebhook } = require('./config/stripe');
const { createPayPalOrder, capturePayPalPayment, verifyPayPalPayment } = require('./config/paypal');
const { sendEmail, emailTemplates } = require('./config/email');

// Admin routes
const adminRoutes = require('./routes/admin');

const app = express();
// ====== CONFIGURATION ======

const PORT = process.env.AUTH_PORT || 8082;
// Enforce presence of a strong JWT secret in production
const JWT_SECRET = process.env.JWT_SECRET || 'nebula-shield-secret-key-change-in-production';
if (process.env.NODE_ENV === 'production' && (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32)) {
  console.error('\u274c Missing or weak JWT_SECRET in production environment. Set process.env.JWT_SECRET with a 32+ char secret.');
  process.exit(1);
}

// Middleware
// Security headers
try {
  const helmet = require('helmet');
  app.use(helmet());
} catch (e) {
  console.warn('helmet not available - install helmet for better security headers');
}

// Rate limiting (protect auth endpoints)
try {
  const rateLimit = require('express-rate-limit');
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false
  });
  app.use('/api/auth', authLimiter);
} catch (e) {
  console.warn('express-rate-limit not available - consider adding it to dependencies');
}

app.use(cors());

// Stripe webhook needs raw body
app.post('/api/payment/stripe/webhook', express.raw({type: 'application/json'}), handleStripeWebhook);

// JSON middleware for all other routes with body size limit
app.use(express.json({ limit: '10kb' }));

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

    // Transactions table for payment tracking
    db.run(`
      CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        order_id TEXT NOT NULL UNIQUE,
        payment_method TEXT NOT NULL,
        amount REAL NOT NULL,
        currency TEXT DEFAULT 'USD',
        status TEXT NOT NULL DEFAULT 'pending',
        transaction_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `, (err) => {
      if (err) console.error('Error creating transactions table:', err);
      else console.log('✅ Transactions table ready');
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

      // Hash password (increase rounds for production)
      const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;
      const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

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

              // Generate token (shorter expiry)
              const token = jwt.sign({ userId, email, tier: 'free' }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '24h' });

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
  body('email').isEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const { email, password } = req.body;

  db.get(
    'SELECT u.* FROM users u WHERE u.email = ?',
    [email],
    async (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (!user) {
        return res.status(401).json({ success: false, message: 'Invalid email or password' });
      }

      // Check user status (suspended/active)
      if (user.status && user.status === 'suspended') {
        return res.status(401).json({ success: false, message: 'Account has been suspended' });
      }

      // Verify password
      const validPassword = await bcrypt.compare(password, user.password_hash);
      
      if (!validPassword) {
        return res.status(401).json({ success: false, message: 'Invalid email or password' });
      }

      // Update last login
      db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

      // Generate token (24h default, configurable via JWT_EXPIRES_IN)
      const tokenPayload = {
        userId: user.id,
        email: user.email,
        tier: user.tier || 'free',
        role: user.role || 'user'
      };

      const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '24h' });

      res.json({
        success: true,
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          email: user.email,
          fullName: user.full_name || user.name,
          tier: user.tier || 'free',
          role: user.role || 'user'
        }
      });
    }
  );
});

// Forgot Password - Send reset email
app.post('/api/auth/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const { email } = req.body;

  // Check if user exists
  db.get('SELECT id, full_name FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    
    // Always return success for security (don't reveal if email exists)
    // In production, you would send an actual email here
    if (user) {
      // TODO: Implement actual email sending
      // For now, we'll just log the reset instructions
      console.log(`\n📧 Password Reset Request`);
      console.log(`Email: ${email}`);
      console.log(`User: ${user.full_name}`);
      console.log(`\nTo reset password, run PowerShell script:`);
      console.log(`cd "Z:\\Directory\\projects\\nebula-shield-anti-virus\\installer"`);
      console.log(`.\\reset-password.ps1\n`);
      
      // In a real app, send email with reset token/link
      // For demo purposes, we'll return success
    }
    
    // Always return success to prevent email enumeration
    res.json({
      success: true,
      message: 'If an account exists with this email, password reset instructions have been sent.'
    });
  });
});

// Verify token and get user info
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  db.get(
    'SELECT u.* FROM users u WHERE u.id = ?',
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
          fullName: user.full_name || user.name,
          tier: user.tier || 'free',
          role: user.role || 'user'
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

// ====== PAYMENT ROUTES ======

// Create Stripe checkout session
app.post('/api/payment/stripe/create-session', authenticateToken, async (req, res) => {
  try {
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id, email, full_name FROM users WHERE id = ?',
        [req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const result = await createStripeCheckoutSession(user.id, user.email, user.full_name);
    
    if (result.success) {
      res.json({
        success: true,
        sessionId: result.sessionId,
        url: result.url
      });
    } else {
      res.status(500).json({
        success: false,
        message: result.error
      });
    }
  } catch (error) {
    console.error('Stripe session error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create payment session'
    });
  }
});

// Verify Stripe payment and upgrade account
app.post('/api/payment/stripe/verify', authenticateToken, async (req, res) => {
  const { sessionId } = req.body;

  if (!sessionId) {
    return res.status(400).json({ success: false, message: 'Session ID required' });
  }

  try {
    const paymentResult = await verifyStripePayment(sessionId);
    
    if (!paymentResult.success) {
      return res.status(400).json({
        success: false,
        message: paymentResult.error
      });
    }

    // Get user details
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id, email, full_name FROM users WHERE id = ?',
        [req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    // Calculate expiration date (1 year from now)
    const expiresAt = new Date();
    expiresAt.setFullYear(expiresAt.getFullYear() + 1);

    // Upgrade subscription
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE subscriptions SET tier = ?, expires_at = ? WHERE user_id = ? AND status = "active"',
        ['premium', expiresAt.toISOString(), req.user.userId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // Record transaction
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO transactions (user_id, order_id, payment_method, amount, status, transaction_id, completed_at)
         VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
        [req.user.userId, paymentResult.orderId, 'Stripe', paymentResult.amount, 'completed', sessionId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // Send confirmation email
    const purchaseData = {
      orderId: paymentResult.orderId,
      amount: paymentResult.amount,
      paymentMethod: 'Stripe (Card)',
      date: new Date().toLocaleDateString(),
      expiresAt: expiresAt.toLocaleDateString()
    };

    const emailTemplate = emailTemplates.purchaseConfirmation(user, purchaseData);
    await sendEmail(user.email, emailTemplate);

    res.json({
      success: true,
      message: 'Payment verified and account upgraded!',
      subscription: {
        tier: 'premium',
        expiresAt: expiresAt.toISOString()
      }
    });
  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Payment verification failed'
    });
  }
});

// Create PayPal order
app.post('/api/payment/paypal/create-order', authenticateToken, async (req, res) => {
  try {
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id, email, full_name FROM users WHERE id = ?',
        [req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const result = await createPayPalOrder(user.id, user.email, user.full_name);
    
    if (result.success) {
      res.json({
        success: true,
        orderId: result.orderId,
        approvalUrl: result.approvalUrl
      });
    } else {
      res.status(500).json({
        success: false,
        message: result.error
      });
    }
  } catch (error) {
    console.error('PayPal order error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create PayPal order'
    });
  }
});

// Capture PayPal payment and upgrade account
app.post('/api/payment/paypal/capture', authenticateToken, async (req, res) => {
  const { orderId } = req.body;

  if (!orderId) {
    return res.status(400).json({ success: false, message: 'Order ID required' });
  }

  try {
    const paymentResult = await capturePayPalPayment(orderId);
    
    if (!paymentResult.success) {
      return res.status(400).json({
        success: false,
        message: paymentResult.error
      });
    }

    // Get user details
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id, email, full_name FROM users WHERE id = ?',
        [req.user.userId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    // Calculate expiration date (1 year from now)
    const expiresAt = new Date();
    expiresAt.setFullYear(expiresAt.getFullYear() + 1);

    // Upgrade subscription
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE subscriptions SET tier = ?, expires_at = ? WHERE user_id = ? AND status = "active"',
        ['premium', expiresAt.toISOString(), req.user.userId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // Record transaction
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO transactions (user_id, order_id, payment_method, amount, status, transaction_id, completed_at)
         VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
        [req.user.userId, paymentResult.orderId, 'PayPal', paymentResult.amount, 'completed', paymentResult.transactionId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // Send confirmation email
    const purchaseData = {
      orderId: paymentResult.orderId,
      amount: paymentResult.amount,
      paymentMethod: 'PayPal',
      date: new Date().toLocaleDateString(),
      expiresAt: expiresAt.toLocaleDateString()
    };

    const emailTemplate = emailTemplates.purchaseConfirmation(user, purchaseData);
    await sendEmail(user.email, emailTemplate);

    res.json({
      success: true,
      message: 'Payment verified and account upgraded!',
      subscription: {
        tier: 'premium',
        expiresAt: expiresAt.toISOString()
      }
    });
  } catch (error) {
    console.error('PayPal capture error:', error);
    res.status(500).json({
      success: false,
      message: 'Payment capture failed'
    });
  }
});

// Get payment history
app.get('/api/payment/history', authenticateToken, (req, res) => {
  db.all(
    'SELECT order_id, payment_method, amount, currency, status, created_at, completed_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.userId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      res.json({
        success: true,
        transactions: rows || []
      });
    }
  );
});

// ====== ANTIVIRUS API ENDPOINTS ======

// Update virus signatures
app.post('/api/signatures/update', (req, res) => {
  try {
    // Simulate signature update process
    const newSignatures = Math.floor(Math.random() * 100) + 20; // 20-120 new signatures
    const totalSignatures = 50000 + newSignatures;
    
    res.json({
      success: true,
      message: 'Virus signatures updated successfully',
      newSignatures: newSignatures,
      totalSignatures: totalSignatures,
      version: '1.0.' + Date.now(),
      lastUpdate: new Date().toISOString(),
      updateDate: Date.now()
    });
  } catch (error) {
    console.error('Error updating signatures:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update signatures'
    });
  }
});

// Quick scan endpoint
app.post('/api/scan/quick', (req, res) => {
  try {
    const { path } = req.body;
    
    // Simulate quick scan
    res.json({
      success: true,
      message: 'Quick scan completed',
      path: path || 'System Memory',
      filesScanned: Math.floor(Math.random() * 1000) + 500,
      threatsFound: Math.floor(Math.random() * 3),
      duration: Math.floor(Math.random() * 30) + 10,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error performing quick scan:', error);
    res.status(500).json({
      success: false,
      message: 'Scan failed'
    });
  }
});

// Full scan endpoint
app.post('/api/scan/full', (req, res) => {
  try {
    const { path } = req.body;
    
    // Simulate full scan (takes longer)
    res.json({
      success: true,
      message: 'Full scan completed',
      path: path || 'C:\\',
      filesScanned: Math.floor(Math.random() * 10000) + 5000,
      threatsFound: Math.floor(Math.random() * 5),
      duration: Math.floor(Math.random() * 120) + 60,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error performing full scan:', error);
    res.status(500).json({
      success: false,
      message: 'Scan failed'
    });
  }
});

// System health endpoint
app.get('/api/system/health', (req, res) => {
  try {
    const os = require('os');
    const memUsage = process.memoryUsage();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    
    // Calculate CPU usage
    const cpus = os.cpus();
    let totalIdle = 0;
    let totalTick = 0;
    cpus.forEach(cpu => {
      for (let type in cpu.times) {
        totalTick += cpu.times[type];
      }
      totalIdle += cpu.times.idle;
    });
    const cpuUsage = 100 - ~~(100 * totalIdle / totalTick);
    
    // Generate mock process list (in production, use real process monitor)
    const mockProcesses = [
      { name: 'Nebula Shield', pid: process.pid, cpu: Math.random() * 10, memory: memUsage.rss, status: 'running' },
      { name: 'Node.js Runtime', pid: process.pid + 1, cpu: Math.random() * 5, memory: memUsage.heapUsed, status: 'running' },
      { name: 'Database Service', pid: process.pid + 2, cpu: Math.random() * 15, memory: 50 * 1024 * 1024, status: 'running' },
      { name: 'Scanner Engine', pid: process.pid + 3, cpu: Math.random() * 20, memory: 120 * 1024 * 1024, status: 'running' },
      { name: 'Network Monitor', pid: process.pid + 4, cpu: Math.random() * 8, memory: 35 * 1024 * 1024, status: 'running' },
      { name: 'File Watcher', pid: process.pid + 5, cpu: Math.random() * 12, memory: 45 * 1024 * 1024, status: 'running' },
      { name: 'Update Service', pid: process.pid + 6, cpu: Math.random() * 3, memory: 25 * 1024 * 1024, status: 'idle' },
      { name: 'Quarantine Manager', pid: process.pid + 7, cpu: Math.random() * 6, memory: 30 * 1024 * 1024, status: 'running' },
      { name: 'Threat Analyzer', pid: process.pid + 8, cpu: Math.random() * 18, memory: 85 * 1024 * 1024, status: 'running' },
      { name: 'Cloud Sync', pid: process.pid + 9, cpu: Math.random() * 4, memory: 20 * 1024 * 1024, status: 'idle' },
      { name: 'UI Renderer', pid: process.pid + 10, cpu: Math.random() * 15, memory: 95 * 1024 * 1024, status: 'running' },
      { name: 'Logger Service', pid: process.pid + 11, cpu: Math.random() * 2, memory: 15 * 1024 * 1024, status: 'running' },
      { name: 'Cache Manager', pid: process.pid + 12, cpu: Math.random() * 7, memory: 40 * 1024 * 1024, status: 'running' },
      { name: 'Backup Service', pid: process.pid + 13, cpu: Math.random() * 5, memory: 28 * 1024 * 1024, status: 'idle' },
      { name: 'Config Watcher', pid: process.pid + 14, cpu: Math.random() * 1, memory: 12 * 1024 * 1024, status: 'running' }
    ];
    
    // Disk usage calculation
    const diskStats = {
      total: 512 * 1024 * 1024 * 1024, // 512 GB
      used: Math.floor(Math.random() * 256 * 1024 * 1024 * 1024), // Random used space
      free: 0
    };
    diskStats.free = diskStats.total - diskStats.used;
    const diskUsagePercent = Math.round((diskStats.used / diskStats.total) * 100);
    
    // Health score calculation
    let healthScore = 100;
    if (cpuUsage > 80) healthScore -= 20;
    else if (cpuUsage > 60) healthScore -= 10;
    
    const memPercent = (usedMem / totalMem) * 100;
    if (memPercent > 85) healthScore -= 20;
    else if (memPercent > 70) healthScore -= 10;
    
    if (diskUsagePercent > 90) healthScore -= 15;
    else if (diskUsagePercent > 75) healthScore -= 5;
    
    let healthStatus = 'healthy';
    let healthMessage = 'All systems operating normally';
    if (healthScore < 70) {
      healthStatus = 'critical';
      healthMessage = 'Critical: System resources critically low';
    } else if (healthScore < 85) {
      healthStatus = 'warning';
      healthMessage = 'Warning: System resources running high';
    }
    
    // Network interfaces
    const networkInterfaces = os.networkInterfaces();
    const interfaces = [];
    for (const [name, iface] of Object.entries(networkInterfaces)) {
      const ipv4 = iface.find(i => i.family === 'IPv4');
      if (ipv4) {
        interfaces.push({ name, address: ipv4.address });
      }
    }
    
    res.json({
      success: true,
      health: {
        status: healthStatus,
        score: healthScore,
        message: healthMessage
      },
      cpu: {
        usage: cpuUsage,
        cores: cpus.length,
        speed: cpus[0].speed,
        model: cpus[0].model,
        temperature: Math.floor(Math.random() * 30) + 40 // Mock temperature 40-70°C
      },
      memory: {
        total: totalMem,
        free: freeMem,
        used: usedMem,
        usagePercent: Math.round(memPercent)
      },
      disk: {
        total: diskStats.total,
        free: diskStats.free,
        used: diskStats.used,
        usagePercent: diskUsagePercent
      },
      network: {
        hostname: os.hostname(),
        interfaces: interfaces
      },
      processes: {
        uptime: Math.floor(process.uptime()),
        platform: os.platform(),
        arch: os.arch(),
        version: process.version,
        memory: memUsage,
        list: mockProcesses
      },
      alerts: healthStatus !== 'healthy' ? [
        healthStatus === 'critical' && { severity: 'critical', message: 'System resources critically low' },
        cpuUsage > 80 && { severity: 'warning', message: `High CPU usage: ${cpuUsage}%` },
        memPercent > 85 && { severity: 'warning', message: `High memory usage: ${Math.round(memPercent)}%` },
        diskUsagePercent > 90 && { severity: 'warning', message: `Disk space critical: ${diskUsagePercent}%` }
      ].filter(Boolean) : [],
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error getting system health:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get system health'
    });
  }
});


// ====== QUARANTINE ENDPOINTS ======

// In-memory quarantine storage (persist to DB in production)
let quarantineStore = [];

// Get all quarantined files
app.get('/api/quarantine', (req, res) => {
  try {
    res.json(quarantineStore);
  } catch (error) {
    console.error('Error fetching quarantine files:', error);
    res.status(500).json({ message: 'Failed to fetch quarantine files' });
  }
});

// Add file to quarantine
app.post('/api/quarantine', (req, res) => {
  try {
    const { fileName, originalPath, threatType, threatName, fileSize, riskLevel } = req.body;
    
    const quarantinedFile = {
      id: Date.now(),
      fileName,
      originalPath,
      quarantinedDate: new Date(),
      threatType,
      threatName,
      fileSize: fileSize || 0,
      riskLevel: riskLevel || 'medium'
    };
    
    quarantineStore.push(quarantinedFile);
    console.log(`📦 File quarantined: ${fileName} (${threatType})`);
    
    res.json({
      success: true,
      message: 'File quarantined successfully',
      file: quarantinedFile
    });
  } catch (error) {
    console.error('Error quarantining file:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to quarantine file' 
    });
  }
});

// Restore file from quarantine
app.post('/api/quarantine/:id/restore', (req, res) => {
  try {
    const fileId = parseInt(req.params.id);
    const fileIndex = quarantineStore.findIndex(f => f.id === fileId);
    
    if (fileIndex === -1) {
      return res.status(404).json({ 
        success: false,
        message: 'File not found in quarantine' 
      });
    }
    
    const file = quarantineStore[fileIndex];
    quarantineStore.splice(fileIndex, 1);
    
    console.log(`♻️ File restored: ${file.fileName}`);
    
    res.json({
      success: true,
      message: 'File restored successfully',
      file: file
    });
  } catch (error) {
    console.error('Error restoring file:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to restore file' 
    });
  }
});

// Delete file from quarantine
app.delete('/api/quarantine/:id', (req, res) => {
  try {
    const fileId = parseInt(req.params.id);
    const fileIndex = quarantineStore.findIndex(f => f.id === fileId);
    
    if (fileIndex === -1) {
      return res.status(404).json({ 
        success: false,
        message: 'File not found in quarantine' 
      });
    }
    
    const file = quarantineStore[fileIndex];
    quarantineStore.splice(fileIndex, 1);
    
    console.log(`🗑️ File permanently deleted: ${file.fileName}`);
    
    res.json({
      success: true,
      message: 'File deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting file:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to delete file' 
    });
  }
});

// Bulk delete quarantined files
app.post('/api/quarantine/bulk/delete', (req, res) => {
  try {
    const { fileIds } = req.body;
    
    if (!Array.isArray(fileIds)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid fileIds array' 
      });
    }
    
    const deletedCount = fileIds.reduce((count, id) => {
      const index = quarantineStore.findIndex(f => f.id === id);
      if (index !== -1) {
        quarantineStore.splice(index, 1);
        return count + 1;
      }
      return count;
    }, 0);
    
    console.log(`🗑️ Bulk deleted ${deletedCount} files from quarantine`);
    
    res.json({
      success: true,
      message: `${deletedCount} files deleted successfully`,
      deleted_count: deletedCount
    });
  } catch (error) {
    console.error('Error bulk deleting files:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to delete files' 
    });
  }
});

// Bulk restore quarantined files
app.post('/api/quarantine/bulk/restore', (req, res) => {
  try {
    const { fileIds } = req.body;
    
    if (!Array.isArray(fileIds)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid fileIds array' 
      });
    }
    
    const restoredFiles = [];
    fileIds.forEach(id => {
      const index = quarantineStore.findIndex(f => f.id === id);
      if (index !== -1) {
        restoredFiles.push(quarantineStore[index]);
        quarantineStore.splice(index, 1);
      }
    });
    
    console.log(`♻️ Bulk restored ${restoredFiles.length} files from quarantine`);
    
    res.json({
      success: true,
      message: `${restoredFiles.length} files restored successfully`,
      restored_count: restoredFiles.length,
      files: restoredFiles
    });
  } catch (error) {
    console.error('Error bulk restoring files:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to restore files' 
    });
  }
});

// Get quarantine statistics
app.get('/api/quarantine/stats', (req, res) => {
  try {
    const stats = {
      total: quarantineStore.length,
      by_risk: {
        critical: quarantineStore.filter(f => f.riskLevel === 'critical').length,
        high: quarantineStore.filter(f => f.riskLevel === 'high').length,
        medium: quarantineStore.filter(f => f.riskLevel === 'medium').length,
        low: quarantineStore.filter(f => f.riskLevel === 'low').length
      },
      by_type: quarantineStore.reduce((acc, file) => {
        acc[file.threatType] = (acc[file.threatType] || 0) + 1;
        return acc;
      }, {}),
      total_size: quarantineStore.reduce((sum, f) => sum + (f.fileSize || 0), 0)
    };
    
    res.json(stats);
  } catch (error) {
    console.error('Error getting quarantine stats:', error);
    res.status(500).json({ message: 'Failed to get quarantine statistics' });
  }
});

// ====== DISK CLEANUP ENDPOINTS ======

// Analyze disk space
app.get('/api/disk/analyze', (req, res) => {
  try {
    // Mock disk analysis data
    // In production, this would use actual filesystem analysis
    const analysis = {
      success: true,
      totalSpace: 512 * 1024 * 1024 * 1024, // 512 GB
      usedSpace: 256 * 1024 * 1024 * 1024, // 256 GB
      freeSpace: 256 * 1024 * 1024 * 1024, // 256 GB
      recycleBin: {
        count: Math.floor(Math.random() * 50) + 10,
        size: Math.floor(Math.random() * 1024 * 1024 * 1024) + 100 * 1024 * 1024 // 100MB - 1GB
      },
      tempFiles: {
        count: Math.floor(Math.random() * 200) + 50,
        size: Math.floor(Math.random() * 2048 * 1024 * 1024) + 500 * 1024 * 1024 // 500MB - 2.5GB
      },
      downloads: {
        count: Math.floor(Math.random() * 30) + 5,
        size: Math.floor(Math.random() * 512 * 1024 * 1024) + 100 * 1024 * 1024 // 100MB - 600MB
      },
      largeFiles: {
        count: Math.floor(Math.random() * 20) + 5,
        size: Math.floor(Math.random() * 5 * 1024 * 1024 * 1024) + 1024 * 1024 * 1024 // 1GB - 6GB
      },
      duplicates: {
        count: Math.floor(Math.random() * 100) + 20,
        size: Math.floor(Math.random() * 1024 * 1024 * 1024) + 200 * 1024 * 1024 // 200MB - 1.2GB
      }
    };
    
    console.log('📊 Disk analysis completed');
    res.json(analysis);
  } catch (error) {
    console.error('Error analyzing disk:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to analyze disk' 
    });
  }
});

// Clean specific category
app.post('/api/disk/clean/:category', (req, res) => {
  try {
    const { category } = req.params;
    
    // Simulate cleanup
    const cleaned = {
      recyclebin: { count: Math.floor(Math.random() * 50), size: Math.floor(Math.random() * 500 * 1024 * 1024) },
      temp: { count: Math.floor(Math.random() * 200), size: Math.floor(Math.random() * 1024 * 1024 * 1024) },
      downloads: { count: Math.floor(Math.random() * 30), size: Math.floor(Math.random() * 300 * 1024 * 1024) }
    };
    
    const result = cleaned[category] || { count: 0, size: 0 };
    
    console.log(`🧹 Cleaned ${category}: ${result.count} items, ${(result.size / 1024 / 1024).toFixed(2)} MB`);
    
    res.json({
      success: true,
      location: category,
      itemsCleaned: result.count,
      spaceCleaned: result.size,
      message: `Successfully cleaned ${result.count} items from ${category}`
    });
  } catch (error) {
    console.error('Error cleaning category:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to clean category' 
    });
  }
});

// Clean all categories
app.post('/api/disk/clean/all', (req, res) => {
  try {
    const recycleBinCleaned = Math.floor(Math.random() * 50) + 10;
    const tempCleaned = Math.floor(Math.random() * 200) + 50;
    const downloadsCleaned = Math.floor(Math.random() * 30) + 5;
    
    const recycleBinSize = Math.floor(Math.random() * 500 * 1024 * 1024) + 100 * 1024 * 1024;
    const tempSize = Math.floor(Math.random() * 1024 * 1024 * 1024) + 500 * 1024 * 1024;
    const downloadsSize = Math.floor(Math.random() * 300 * 1024 * 1024) + 100 * 1024 * 1024;
    
    const totalCleaned = recycleBinSize + tempSize + downloadsSize;
    const totalItems = recycleBinCleaned + tempCleaned + downloadsCleaned;
    
    console.log(`🧹 Full cleanup: ${totalItems} items, ${(totalCleaned / 1024 / 1024 / 1024).toFixed(2)} GB freed`);
    
    res.json({
      success: true,
      totalCleaned: totalCleaned,
      itemsCleaned: totalItems,
      message: `Successfully cleaned ${totalItems} items and freed ${(totalCleaned / 1024 / 1024 / 1024).toFixed(2)} GB`,
      details: {
        recyclebin: { count: recycleBinCleaned, size: recycleBinSize },
        temp: { count: tempCleaned, size: tempSize },
        downloads: { count: downloadsCleaned, size: downloadsSize }
      }
    });
  } catch (error) {
    console.error('Error performing full cleanup:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to perform full cleanup' 
    });
  }
});

// ====== CONFIGURATION ENDPOINTS ======

// Get configuration
app.get('/api/config', (req, res) => {
  try {
    // Return default configuration
    res.json({
      realTimeProtection: true,
      scheduledScans: true,
      autoQuarantine: true,
      notifications: true,
      scanDepth: 'medium',
      updateFrequency: 'daily',
      exclusions: [],
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error getting configuration:', error);
    res.status(500).json({ message: 'Failed to get configuration' });
  }
});

// Update configuration
app.post('/api/config', (req, res) => {
  try {
    const config = req.body;
    console.log('📝 Configuration updated:', config);
    
    res.json({
      success: true,
      message: 'Configuration updated successfully',
      config: config
    });
  } catch (error) {
    console.error('Error updating configuration:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to update configuration' 
    });
  }
});

// Legacy /status endpoint (without /api prefix)
app.get('/status', (req, res) => {
  try {
    res.json({
      success: true,
      real_time_protection: true,
      total_scanned_files: Math.floor(Math.random() * 10000) + 5000,
      total_threats_found: Math.floor(Math.random() * 10),
      last_scan_time: new Date().toISOString(),
      database_version: '2025.10.24',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error getting status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get status'
    });
  }
});

// Legacy /config endpoint (without /api prefix)
app.get('/config', (req, res) => {
  try {
    res.json({
      realTimeProtection: true,
      scheduledScans: true,
      autoQuarantine: true,
      notifications: true,
      scanDepth: 'medium',
      updateFrequency: 'daily',
      exclusions: [],
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error getting config:', error);
    res.status(500).json({ message: 'Failed to get config' });
  }
});

app.post('/config', (req, res) => {
  try {
    const config = req.body;
    console.log('📝 Config updated:', config);
    
    res.json({
      success: true,
      message: 'Configuration updated successfully',
      config: config
    });
  } catch (error) {
    console.error('Error updating config:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to update config' 
    });
  }
});

// Protection status endpoint (for frontend dashboard)
app.get('/api/status', (req, res) => {
  try {
    // Return mock protection status for now
    // TODO: Connect to actual C++ backend or tracking service
    res.json({
      success: true,
      real_time_protection: true,
      total_scanned_files: Math.floor(Math.random() * 10000) + 5000,
      total_threats_found: Math.floor(Math.random() * 10),
      last_scan_time: new Date().toISOString(),
      database_version: '2025.10.24',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error getting protection status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get protection status'
    });
  }
});

// ====== SERVER ======

// Test route
app.get('/test', (req, res) => {
  console.log('✅ Test route hit!');
  res.json({ message: 'Server is working!' });
});

// Mount admin routes with authentication
app.use('/api/admin', authenticateToken, adminRoutes);

const server = app.listen(PORT, () => {
  console.log(`\n🔐 Nebula Shield Auth Server`);
  console.log(`📡 Listening on port ${PORT}`);
  console.log(`🔑 JWT authentication enabled`);
  console.log(`🛡️ Admin API enabled at /api/admin\n`);
});

// Keep server alive
server.on('error', (err) => {
  console.error('❌ Server error:', err);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down auth server...');
  db.close((err) => {
    if (err) console.error('Error closing database:', err);
    else console.log('✅ Database closed');
    server.close(() => {
      process.exit(0);
    });
  });
});
