/**
 * Authentication Routes
 * Handle user login, registration, token refresh
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const inputSanitizer = require('../../backend/security/input-sanitizer');
const router = express.Router();

const JWT_ISSUER = process.env.JWT_ISSUER || 'nebula-shield';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'nebula-shield-app';

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many login attempts. Please try again later.'
  }
});

// Temporary in-memory user store (replace with database)
const users = new Map();

// Note: Users can register through /api/auth/register endpoint
// In production, replace with a proper database (PostgreSQL, MongoDB, etc.)

/**
 * POST /api/auth/login
 * Authenticate user and return JWT token
 */
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password required'
      });
    }

    if (typeof password !== 'string' || password.length > 256) {
      return res.status(400).json({
        success: false,
        error: 'Invalid password format'
      });
    }

    let normalizedEmail;
    try {
      normalizedEmail = inputSanitizer.sanitizeEmail(email);
    } catch (error) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format'
      });
    }

    const user = users.get(normalizedEmail);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      {
        expiresIn: '7d',
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE
      }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Login failed'
    });
  }
});

/**
 * POST /api/auth/register
 * Register new user
 */
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { email, password, fullName } = req.body;

    if (!email || !password || !fullName) {
      return res.status(400).json({
        success: false,
        error: 'Email, password, and full name required'
      });
    }

    let normalizedEmail;
    try {
      normalizedEmail = inputSanitizer.sanitizeEmail(email);
    } catch (error) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format'
      });
    }

    if (typeof password !== 'string' || password.length > 256) {
      return res.status(400).json({
        success: false,
        error: 'Invalid password format'
      });
    }

    const passwordCheck = inputSanitizer.validatePassword(password);
    if (!passwordCheck.valid) {
      return res.status(400).json({
        success: false,
        error: passwordCheck.message
      });
    }

    const sanitizedName = inputSanitizer.sanitizeString(fullName, {
      trim: true,
      maxLength: 80,
      escapeHtml: true,
      preventXSS: true
    });

    if (users.has(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        error: 'Email already registered'
      });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user
    const userId = (users.size + 1).toString();
    const user = {
      id: userId,
      email: normalizedEmail,
      passwordHash,
      fullName: sanitizedName,
      createdAt: new Date()
    };

    users.set(normalizedEmail, user);

    // Generate token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      {
        expiresIn: '7d',
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE
      }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      error: 'Registration failed'
    });
  }
});

/**
 * POST /api/auth/verify
 * Verify JWT token
 */
router.post('/verify', (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        error: 'Token required'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE
    });
    const user = Array.from(users.values()).find(u => u.id === decoded.id);

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User not found'
      });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName
      }
    });

  } catch (error) {
    res.status(401).json({
      success: false,
      error: 'Invalid token'
    });
  }
});

module.exports = router;
