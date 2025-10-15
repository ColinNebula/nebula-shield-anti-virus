/**
 * Nebula Shield - Create Default Admin Account
 * This script creates a default administrator account after installation
 * Built by Colin Nebula for Nebula3ddev.com
 */

const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

// Default admin credentials
const DEFAULT_ADMIN = {
  email: 'admin@nebulashield.local',
  password: 'NebulaAdmin2025!',
  fullName: 'Nebula Shield Administrator',
  role: 'admin',
  tier: 'premium'
};

// Get database path
const dbPath = path.join(__dirname, '..', 'data', 'auth.db');

console.log('\n╔════════════════════════════════════════════════╗');
console.log('║  Nebula Shield - Creating Default Admin       ║');
console.log('╚════════════════════════════════════════════════╝\n');

// Check if database exists
if (!fs.existsSync(dbPath)) {
  console.error('❌ Database not found at:', dbPath);
  console.error('   Please ensure the auth server has run at least once.');
  process.exit(1);
}

console.log('✅ Database found:', dbPath);

// Connect to database
const db = new sqlite3.Database(dbPath, async (err) => {
  if (err) {
    console.error('❌ Failed to connect to database:', err.message);
    process.exit(1);
  }

  console.log('✅ Connected to auth database\n');

  try {
    // Check if admin already exists
    db.get('SELECT * FROM users WHERE email = ?', [DEFAULT_ADMIN.email], async (err, existingUser) => {
      if (err) {
        console.error('❌ Database query error:', err.message);
        db.close();
        process.exit(1);
      }

      if (existingUser) {
        console.log('ℹ️  Default admin already exists');
        console.log('   Email:', existingUser.email);
        console.log('   If you forgot the password, use reset-password.ps1');
        db.close();
        process.exit(0);
      }

      // Hash the password
      console.log('🔐 Hashing password...');
      const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN.password, 10);
      console.log('✅ Password hashed\n');

      // Insert admin user
      console.log('👤 Creating admin account...');
      db.run(
        'INSERT INTO users (email, password_hash, full_name, role, tier, status) VALUES (?, ?, ?, ?, ?, ?)',
        [DEFAULT_ADMIN.email, hashedPassword, DEFAULT_ADMIN.fullName, DEFAULT_ADMIN.role, DEFAULT_ADMIN.tier, 'active'],
        function(err) {
          if (err) {
            console.error('❌ Failed to create admin:', err.message);
            db.close();
            process.exit(1);
          }

          const userId = this.lastID;
          console.log('✅ Admin account created (ID:', userId + ')\n');

          // Create subscription record
          db.run(
            'INSERT INTO subscriptions (user_id, tier, status) VALUES (?, ?, ?)',
            [userId, 'premium', 'active'],
            (err) => {
              if (err) {
                console.warn('⚠️  Could not create subscription record:', err.message);
              } else {
                console.log('✅ Premium subscription activated\n');
              }

              // Display credentials
              console.log('╔════════════════════════════════════════════════╗');
              console.log('║           DEFAULT ADMIN CREDENTIALS            ║');
              console.log('╠════════════════════════════════════════════════╣');
              console.log('║                                                ║');
              console.log('║  Email:    admin@nebulashield.local            ║');
              console.log('║  Password: NebulaAdmin2025!                    ║');
              console.log('║  Tier:     Premium                             ║');
              console.log('║  Role:     Administrator                       ║');
              console.log('║                                                ║');
              console.log('╠════════════════════════════════════════════════╣');
              console.log('║  ⚠️  IMPORTANT SECURITY NOTICE                 ║');
              console.log('║                                                ║');
              console.log('║  Please change this password after first login ║');
              console.log('║  Go to Settings → Account → Change Password    ║');
              console.log('║                                                ║');
              console.log('╚════════════════════════════════════════════════╝\n');

              console.log('✅ Setup complete!\n');
              console.log('Login at: http://localhost:3001\n');

              db.close();
              process.exit(0);
            }
          );
        }
      );
    });
  } catch (error) {
    console.error('❌ Error:', error.message);
    db.close();
    process.exit(1);
  }
});
