/**
 * Check if any IPs are blocked by Enhanced Hacker Protection
 * Run with: node check-blocked-ips.js
 */

const enhancedHackerProtection = require('./backend/enhanced-hacker-protection');

console.log('\n🔍 Checking Enhanced Hacker Protection Status...\n');

// Get blocked IPs
const blockedIPs = enhancedHackerProtection.state.blockedIPs;
console.log('📊 Blocked IPs:', blockedIPs.size);

if (blockedIPs.size > 0) {
  console.log('\n❌ Currently Blocked IPs:');
  blockedIPs.forEach((info, ip) => {
    const remaining = Math.ceil((info.expiresAt - Date.now()) / 60000);
    console.log(`  IP: ${ip}`);
    console.log(`  Reason: ${info.reason}`);
    console.log(`  Blocked at: ${new Date(info.blockedAt).toLocaleString()}`);
    console.log(`  Expires in: ${remaining > 0 ? remaining + ' minutes' : 'EXPIRED'}`);
    console.log(`  Block count: ${info.count}`);
    console.log('');
  });
}

// Get failed attempts
const failedAttempts = enhancedHackerProtection.state.failedAttempts;
console.log('📊 IPs with failed attempts:', failedAttempts.size);

if (failedAttempts.size > 0) {
  console.log('\n⚠️ Failed Login Attempts:');
  failedAttempts.forEach((attempts, ip) => {
    console.log(`  IP: ${ip} - ${attempts.length} attempts`);
  });
  console.log('');
}

// Get suspicious IPs
const suspiciousIPs = enhancedHackerProtection.state.suspiciousIPs;
console.log('📊 Suspicious IPs:', suspiciousIPs.size);

if (suspiciousIPs.size > 0) {
  console.log('\n⚠️ Suspicious IPs:');
  suspiciousIPs.forEach((info, ip) => {
    console.log(`  IP: ${ip}`);
    console.log(`  Threats: ${info.threats.map(t => t.type).join(', ')}`);
    console.log('');
  });
}

// Check stats
const stats = enhancedHackerProtection.getStatistics();
console.log('📈 Statistics:');
console.log(`  Total Requests: ${stats.totalRequests}`);
console.log(`  Attacks Blocked: ${stats.totalAttacksBlocked}`);
console.log(`  Currently Blocked: ${stats.blockedIPCount}`);
console.log(`  Suspicious: ${stats.suspiciousIPCount}`);

// Clear all blocks (helpful for development)
if (blockedIPs.size > 0) {
  console.log('\n🧹 Clearing all blocked IPs...');
  blockedIPs.forEach((info, ip) => {
    enhancedHackerProtection.unblockIP(ip);
  });
  console.log('✅ All IPs unblocked!');
}

if (failedAttempts.size > 0) {
  console.log('\n🧹 Clearing failed attempts...');
  failedAttempts.clear();
  console.log('✅ Failed attempts cleared!');
}

console.log('\n✨ You should now be able to log in!\n');

setTimeout(() => process.exit(0), 1000);
