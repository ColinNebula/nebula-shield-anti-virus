// Nebula Shield - Centralized Configuration
// Single source of truth for all services

// Service Ports
const PORTS = {
  FRONTEND: 3000,
  AUTH_SERVER: 8082,
  BACKEND_API: 8080,
  WEBSOCKET: 3001  // For real-time sync
};

// API Endpoints
const API_ENDPOINTS = {
  AUTH_BASE: `http://localhost:${PORTS.AUTH_SERVER}/api/auth`,
  ADMIN_BASE: `http://localhost:${PORTS.AUTH_SERVER}/api/admin`,
  BACKEND_BASE: `http://localhost:${PORTS.BACKEND_API}/api`,
  SUBSCRIPTION: `http://localhost:${PORTS.AUTH_SERVER}/api/subscription`,
  PAYMENT: `http://localhost:${PORTS.AUTH_SERVER}/api/payment`
};

// Database Configuration
const DATABASE = {
  PATH: '../data/auth.db',
  SCHEMA_VERSION: '2.0.0',  // Track schema changes
  MIGRATIONS_DIR: '../backend/migrations'
};

// Feature Flags - Control what's enabled across all services
const FEATURES = {
  ADMIN_PANEL: true,
  RBAC: true,
  AUDIT_LOGS: true,
  REAL_TIME_SYNC: true,
  PAYMENT_STRIPE: true,
  PAYMENT_PAYPAL: true,
  EMAIL_NOTIFICATIONS: false,
  TWO_FACTOR_AUTH: false,
  
  // Protection Features
  REAL_TIME_PROTECTION: true,
  WEB_PROTECTION: true,
  EMAIL_PROTECTION: true,
  RANSOMWARE_PROTECTION: true,
  DRIVER_SCANNER: true,
  NETWORK_PROTECTION: true,
  HACKER_PROTECTION: true
};

// User Roles & Permissions
const ROLES = {
  ADMIN: {
    name: 'admin',
    permissions: ['*']  // All permissions
  },
  USER: {
    name: 'user',
    permissions: ['scan', 'view_dashboard', 'manage_settings', 'quarantine']
  },
  VIEWER: {
    name: 'viewer',
    permissions: ['view_dashboard']
  }
};

// Tier Configuration
const TIERS = {
  FREE: {
    name: 'free',
    features: ['quick_scan', 'basic_protection', 'manual_scan']
  },
  PREMIUM: {
    name: 'premium',
    features: [
      'quick_scan',
      'full_scan',
      'custom_scan',
      'scheduled_scans',
      'advanced_protection',
      'pdf_reports',
      'custom_scan_paths',
      'priority_support'
    ]
  }
};

// Service Health Check Intervals
const HEALTH_CHECK = {
  INTERVAL: 5000,  // 5 seconds
  TIMEOUT: 3000,   // 3 seconds
  RETRY_ATTEMPTS: 3
};

// Sync Configuration
const SYNC = {
  ENABLED: true,
  BROADCAST_EVENTS: [
    'user_created',
    'user_updated',
    'user_deleted',
    'role_changed',
    'tier_changed',
    'feature_toggled',
    'scan_completed',
    'threat_detected',
    'settings_updated'
  ]
};

// Current Version
const VERSION = '2.0.0';
const BUILD_DATE = '2025-10-12';

module.exports = {
  PORTS,
  API_ENDPOINTS,
  DATABASE,
  FEATURES,
  ROLES,
  TIERS,
  HEALTH_CHECK,
  SYNC,
  VERSION,
  BUILD_DATE
};
