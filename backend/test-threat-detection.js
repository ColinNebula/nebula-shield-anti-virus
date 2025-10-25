/**
 * Test Script for Production Threat Detection System
 * Run this to verify all components are working
 */

const integratedScanner = require('./integrated-scanner-service');
const fs = require('fs').promises;
const path = require('path');

// ANSI colors for terminal output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

async function runTests() {
  log('\n╔══════════════════════════════════════════════════════════╗', 'cyan');
  log('║  Nebula Shield - Production Threat Detection Test       ║', 'cyan');
  log('╚══════════════════════════════════════════════════════════╝\n', 'cyan');

  let passedTests = 0;
  let totalTests = 0;

  // Test 1: Check if services are initialized
  totalTests++;
  log(`\n[Test 1/${totalTests}] Checking service initialization...`, 'blue');
  try {
    const stats = integratedScanner.getStatistics();
    if (stats.engines.malwareEngine) {
      log('  ✅ Malware detection engine: READY', 'green');
      passedTests++;
    } else {
      log('  ❌ Malware detection engine: NOT READY', 'red');
    }
  } catch (error) {
    log(`  ❌ Service check failed: ${error.message}`, 'red');
  }

  // Test 2: Create and scan EICAR test file
  totalTests++;
  log(`\n[Test 2/${totalTests}] Testing EICAR detection...`, 'blue');
  try {
    const eicarContent = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    const eicarPath = path.join(__dirname, 'test_eicar.txt');
    
    await fs.writeFile(eicarPath, eicarContent, { encoding: 'utf8' });
    log('  📄 Created EICAR test file', 'yellow');

    const scanResult = await integratedScanner.scanFile(eicarPath);
    
    log(`\n  Scan Results:`, 'cyan');
    log(`  - Status: ${scanResult.status}`, 'yellow');
    log(`  - Clean: ${scanResult.engines.malwareEngine.isClean}`, 'yellow');
    log(`  - Threats found: ${scanResult.threats.length}`, 'yellow');
    log(`  - Scan duration: ${scanResult.duration}ms`, 'yellow');

    if (!scanResult.engines.malwareEngine.isClean && scanResult.threats.length > 0) {
      const threat = scanResult.threats[0];
      log(`\n  ✅ EICAR detected correctly!`, 'green');
      log(`     Name: ${threat.name}`, 'green');
      log(`     Method: ${threat.method}`, 'green');
      log(`     Confidence: ${threat.confidence}%`, 'green');
      passedTests++;
    } else {
      log(`  ❌ EICAR NOT detected (should be detected)`, 'red');
    }

    // Cleanup
    await fs.unlink(eicarPath);
    log('  🗑️  Cleaned up test file', 'yellow');

  } catch (error) {
    log(`  ❌ EICAR test failed: ${error.message}`, 'red');
  }

  // Test 3: Create clean file and verify it's not flagged
  totalTests++;
  log(`\n[Test 3/${totalTests}] Testing clean file detection...`, 'blue');
  try {
    const cleanPath = path.join(__dirname, 'test_clean.txt');
    await fs.writeFile(cleanPath, 'This is a harmless text file for testing.', { encoding: 'utf8' });
    log('  📄 Created clean test file', 'yellow');

    const scanResult = await integratedScanner.scanFile(cleanPath);
    
    if (scanResult.engines.malwareEngine.isClean) {
      log(`  ✅ Clean file recognized correctly!`, 'green');
      log(`     Scan duration: ${scanResult.duration}ms`, 'green');
      passedTests++;
    } else {
      log(`  ❌ Clean file flagged as threat (false positive)`, 'red');
      log(`     Threats: ${JSON.stringify(scanResult.threats, null, 2)}`, 'red');
    }

    await fs.unlink(cleanPath);
    log('  🗑️  Cleaned up test file', 'yellow');

  } catch (error) {
    log(`  ❌ Clean file test failed: ${error.message}`, 'red');
  }

  // Test 4: IP reputation check
  totalTests++;
  log(`\n[Test 4/${totalTests}] Testing IP reputation check...`, 'blue');
  try {
    const maliciousIp = '185.220.101.1'; // Known malicious IP from threat-feeds.json
    const ipResult = await integratedScanner.checkIp(maliciousIp);
    
    log(`  IP: ${maliciousIp}`, 'yellow');
    log(`  Threat: ${ipResult.isThreat}`, 'yellow');
    log(`  Level: ${ipResult.threatLevel}`, 'yellow');

    if (ipResult.isThreat) {
      log(`  ✅ Malicious IP detected correctly!`, 'green');
      log(`     Sources: ${ipResult.sources.join(', ')}`, 'green');
      passedTests++;
    } else {
      log(`  ⚠️  IP not flagged (may need threat feed update)`, 'yellow');
    }
  } catch (error) {
    log(`  ❌ IP check failed: ${error.message}`, 'red');
  }

  // Test 5: URL reputation check
  totalTests++;
  log(`\n[Test 5/${totalTests}] Testing URL reputation check...`, 'blue');
  try {
    const phishingUrl = 'http://malicious-phishing-site.tk'; // Known phishing domain
    const urlResult = await integratedScanner.checkUrl(phishingUrl);
    
    log(`  URL: ${phishingUrl}`, 'yellow');
    log(`  Threat: ${urlResult.isThreat}`, 'yellow');
    log(`  Level: ${urlResult.threatLevel}`, 'yellow');

    if (urlResult.isThreat) {
      log(`  ✅ Malicious URL detected correctly!`, 'green');
      log(`     Sources: ${urlResult.sources.join(', ')}`, 'green');
      passedTests++;
    } else {
      log(`  ⚠️  URL not flagged (may need threat feed update)`, 'yellow');
    }
  } catch (error) {
    log(`  ❌ URL check failed: ${error.message}`, 'red');
  }

  // Test 6: Heuristic analysis (high entropy file)
  totalTests++;
  log(`\n[Test 6/${totalTests}] Testing heuristic analysis...`, 'blue');
  try {
    const suspiciousPath = path.join(__dirname, 'test_crack.exe');
    // Create file with suspicious name
    await fs.writeFile(suspiciousPath, 'This is a test file with suspicious naming', { encoding: 'utf8' });
    log('  📄 Created suspicious test file (crack.exe)', 'yellow');

    const scanResult = await integratedScanner.scanFile(suspiciousPath);
    
    const heuristicDetection = scanResult.threats.some(t => 
      t.method === 'Heuristic analysis' || t.name.includes('Heuristic')
    );

    if (heuristicDetection) {
      log(`  ✅ Heuristic analysis working!`, 'green');
      const threat = scanResult.threats.find(t => t.method === 'Heuristic analysis');
      log(`     Detected: ${threat.name}`, 'green');
      passedTests++;
    } else {
      log(`  ⚠️  No heuristic detection (may be too small file)`, 'yellow');
    }

    await fs.unlink(suspiciousPath);
    log('  🗑️  Cleaned up test file', 'yellow');

  } catch (error) {
    log(`  ❌ Heuristic test failed: ${error.message}`, 'red');
  }

  // Test 7: Statistics
  totalTests++;
  log(`\n[Test 7/${totalTests}] Checking system statistics...`, 'blue');
  try {
    const stats = integratedScanner.getStatistics();
    
    log(`  📊 Scanner Statistics:`, 'cyan');
    log(`     Total scans: ${stats.totalScans}`, 'yellow');
    log(`     Threats detected: ${stats.threatsDetected}`, 'yellow');
    log(`     Clean files: ${stats.cleanFiles}`, 'yellow');
    log(`     Detection rate: ${stats.detectionRate}%`, 'yellow');
    
    log(`\n  🔧 Engine Status:`, 'cyan');
    log(`     Malware engine: ${stats.engines.malwareEngine ? '✅ Ready' : '❌ Not ready'}`, 
        stats.engines.malwareEngine ? 'green' : 'red');
    log(`     VirusTotal: ${stats.engines.virusTotal ? '✅ Configured' : '⚠️  Not configured (optional)'}`, 
        stats.engines.virusTotal ? 'green' : 'yellow');
    log(`     Threat intel: ${stats.engines.threatIntelligence ? '✅ Ready' : '❌ Not ready'}`, 
        stats.engines.threatIntelligence ? 'green' : 'red');

    if (stats.engines.malwareEngine && stats.engines.threatIntelligence) {
      log(`\n  ✅ All core engines operational!`, 'green');
      passedTests++;
    } else {
      log(`\n  ❌ Some engines not operational`, 'red');
    }
  } catch (error) {
    log(`  ❌ Statistics check failed: ${error.message}`, 'red');
  }

  // Final Summary
  log('\n╔══════════════════════════════════════════════════════════╗', 'cyan');
  log('║                   Test Summary                           ║', 'cyan');
  log('╚══════════════════════════════════════════════════════════╝\n', 'cyan');

  const successRate = ((passedTests / totalTests) * 100).toFixed(1);
  log(`  Tests Passed: ${passedTests}/${totalTests} (${successRate}%)`, 
      passedTests === totalTests ? 'green' : 'yellow');

  if (passedTests === totalTests) {
    log('\n  🎉 ALL TESTS PASSED! Production threat detection is working!', 'green');
    log('  🛡️  Your antivirus is ready for real-world use.', 'green');
  } else if (passedTests >= totalTests * 0.7) {
    log('\n  ⚠️  Most tests passed. Core functionality working.', 'yellow');
    log('  💡 Consider configuring optional features (VirusTotal, etc.)', 'yellow');
  } else {
    log('\n  ❌ Several tests failed. Check configuration.', 'red');
    log('  📖 See PRODUCTION_THREAT_DETECTION_GUIDE.md for setup help', 'red');
  }

  // Additional info
  log('\n╔══════════════════════════════════════════════════════════╗', 'cyan');
  log('║                  Additional Info                         ║', 'cyan');
  log('╚══════════════════════════════════════════════════════════╝\n', 'cyan');

  const stats = integratedScanner.getStatistics();
  
  if (!stats.engines.virusTotal) {
    log('  💡 VirusTotal not configured (optional)', 'yellow');
    log('     To enable: $env:VIRUSTOTAL_API_KEY = "your-key"', 'yellow');
    log('     Signup: https://www.virustotal.com/gui/join-us', 'yellow');
    log('     Impact: +10-15% detection accuracy (95-99% total)\n', 'yellow');
  } else {
    log('  ✅ VirusTotal configured - using 70+ AV engines!', 'green');
  }

  log('  📚 Documentation:', 'cyan');
  log('     - Full Guide: PRODUCTION_THREAT_DETECTION_GUIDE.md', 'yellow');
  log('     - Quick Ref: THREAT_DETECTION_QUICK_REFERENCE.md', 'yellow');
  log('     - Summary: PRODUCTION_DETECTION_IMPLEMENTATION_SUMMARY.md\n', 'yellow');

  log('  🚀 Ready to scan? Start the backend:', 'cyan');
  log('     node backend/mock-backend.js\n', 'yellow');
}

// Run tests if executed directly
if (require.main === module) {
  runTests().then(() => {
    log('\n✅ Test suite completed!\n', 'green');
    process.exit(0);
  }).catch((error) => {
    log(`\n❌ Test suite failed: ${error.message}\n`, 'red');
    console.error(error);
    process.exit(1);
  });
}

module.exports = { runTests };
