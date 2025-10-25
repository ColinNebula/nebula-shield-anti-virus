/**
 * Quick script to unlock a locked account
 * Run with: node unlock-account.js
 */

const authService = require('./backend/auth-service');

// Unlock the account
const email = 'colinnebula@gmail.com';
const user = authService.users.get(email);

if (user) {
  console.log('\n🔓 Unlocking account:', email);
  console.log('Current status:');
  console.log('  Failed attempts:', user.failedAttempts);
  console.log('  Locked until:', user.lockedUntil ? new Date(user.lockedUntil) : 'Not locked');
  
  // Reset the lock
  user.failedAttempts = 0;
  user.lockedUntil = null;
  
  console.log('\n✅ Account unlocked successfully!');
  console.log('You can now log in with:');
  console.log('  Email:', email);
  console.log('  Password: Nebula2025!\n');
} else {
  console.log('\n❌ User not found:', email, '\n');
}

// Keep the script running for a moment so you can see the output
setTimeout(() => {
  console.log('Done!');
  process.exit(0);
}, 1000);
