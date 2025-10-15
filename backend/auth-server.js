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
const JWT_SECRET = process.env.JWT_SECRET || 'nebula-shield-secret-key-change-in-production';

// Middleware
app.use(cors());

// Stripe webhook needs raw body
app.post('/api/payment/stripe/webhook', express.raw({type: 'application/json'}), handleStripeWebhook);

// JSON middleware for all other routes
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

      // Generate token
      const token = jwt.sign(
        { 
          userId: user.id, 
          email: user.email, 
          tier: user.tier || 'free',
          role: user.role || 'user'
        },
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
