// Code Integrity Checker
// Verifies that critical files haven't been tampered with
// Run this before starting the application

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class IntegrityChecker {
  constructor() {
    this.checksums = new Map();
    this.criticalFiles = [
      'mock-backend-secure.js',
      'src/services/mlAnomalyDetection.js',
      'src/services/emailVerification.js',
      'src/contexts/AuthContext.js',
      'src/middleware/security.js',
      'package.json'
    ];
  }

  // Calculate file hash
  calculateHash(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      return crypto.createHash('sha256').update(content).digest('hex');
    } catch (error) {
      console.error(`Error reading file ${filePath}:`, error.message);
      return null;
    }
  }

  // Generate checksums for all critical files
  generateChecksums() {
    console.log('🔐 Generating file checksums...\n');

    const checksums = {};
    let generated = 0;

    this.criticalFiles.forEach(file => {
      const filePath = path.join(__dirname, '..', '..', file);
      const hash = this.calculateHash(filePath);
      
      if (hash) {
        checksums[file] = hash;
        generated++;
        console.log(`✅ ${file}`);
        console.log(`   SHA-256: ${hash}\n`);
      } else {
        console.log(`❌ ${file} - Failed to generate hash\n`);
      }
    });

    // Save checksums to file
    const checksumsPath = path.join(__dirname, '..', '..', '.checksums.json');
    fs.writeFileSync(checksumsPath, JSON.stringify(checksums, null, 2));

    console.log(`\n📝 Generated ${generated}/${this.criticalFiles.length} checksums`);
    console.log(`💾 Saved to: .checksums.json\n`);

    return checksums;
  }

  // Verify file integrity
  verifyIntegrity() {
    console.log('🔍 Verifying file integrity...\n');

    const checksumsPath = path.join(__dirname, '..', '..', '.checksums.json');

    if (!fs.existsSync(checksumsPath)) {
      console.log('❌ No checksums file found. Run: npm run generate-checksums\n');
      return false;
    }

    const storedChecksums = JSON.parse(fs.readFileSync(checksumsPath, 'utf8'));
    let verified = 0;
    let failed = 0;
    let missing = 0;

    this.criticalFiles.forEach(file => {
      const filePath = path.join(__dirname, '..', '..', file);
      
      if (!fs.existsSync(filePath)) {
        console.log(`⚠️  ${file} - File not found`);
        missing++;
        return;
      }

      const currentHash = this.calculateHash(filePath);
      const storedHash = storedChecksums[file];

      if (!storedHash) {
        console.log(`⚠️  ${file} - No stored checksum`);
        missing++;
        return;
      }

      if (currentHash === storedHash) {
        console.log(`✅ ${file} - Integrity verified`);
        verified++;
      } else {
        console.log(`❌ ${file} - INTEGRITY FAILED!`);
        console.log(`   Expected: ${storedHash}`);
        console.log(`   Found:    ${currentHash}`);
        failed++;
      }
    });

    console.log(`\n📊 Verification Results:`);
    console.log(`   ✅ Verified: ${verified}`);
    console.log(`   ❌ Failed: ${failed}`);
    console.log(`   ⚠️  Missing: ${missing}`);

    if (failed > 0) {
      console.log('\n🚨 SECURITY ALERT: File integrity check failed!');
      console.log('   Some files have been modified.');
      console.log('   DO NOT run the application if you did not make these changes.\n');
      return false;
    }

    if (missing > 0) {
      console.log('\n⚠️  WARNING: Some checksums are missing.');
      console.log('   Run: npm run generate-checksums\n');
    }

    if (verified === this.criticalFiles.length) {
      console.log('\n✅ All files passed integrity check!\n');
    }

    return true;
  }

  // Watch for file changes
  watchFiles() {
    console.log('👁️  Watching critical files for changes...\n');

    this.criticalFiles.forEach(file => {
      const filePath = path.join(__dirname, '..', '..', file);
      
      if (fs.existsSync(filePath)) {
        fs.watch(filePath, (eventType, filename) => {
          if (eventType === 'change') {
            console.log(`\n⚠️  File modified: ${file}`);
            console.log(`   Event: ${eventType}`);
            console.log(`   Time: ${new Date().toISOString()}`);
            
            // Verify integrity after change
            const currentHash = this.calculateHash(filePath);
            console.log(`   New SHA-256: ${currentHash}\n`);
          }
        });
        console.log(`👁️  Watching: ${file}`);
      }
    });

    console.log('\n✅ File monitoring active\n');
  }

  // Generate integrity report
  generateReport() {
    console.log('📋 Generating Integrity Report...\n');
    console.log('=' .repeat(60));
    console.log('NEBULA SHIELD ANTI-VIRUS - FILE INTEGRITY REPORT');
    console.log('=' .repeat(60));
    console.log(`Generated: ${new Date().toISOString()}\n`);

    const report = {
      timestamp: new Date().toISOString(),
      files: []
    };

    this.criticalFiles.forEach(file => {
      const filePath = path.join(__dirname, '..', '..', file);
      const exists = fs.existsSync(filePath);
      
      const fileReport = {
        path: file,
        exists,
        hash: exists ? this.calculateHash(filePath) : null,
        size: exists ? fs.statSync(filePath).size : 0,
        modified: exists ? fs.statSync(filePath).mtime : null
      };

      report.files.push(fileReport);

      console.log(`File: ${file}`);
      console.log(`  Status: ${exists ? '✅ Exists' : '❌ Missing'}`);
      if (exists) {
        console.log(`  SHA-256: ${fileReport.hash}`);
        console.log(`  Size: ${fileReport.size} bytes`);
        console.log(`  Modified: ${fileReport.modified}`);
      }
      console.log('');
    });

    // Save report
    const reportPath = path.join(__dirname, '..', '..', 'integrity-report.json');
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

    console.log('=' .repeat(60));
    console.log(`💾 Report saved to: integrity-report.json\n`);

    return report;
  }

  // Compare with baseline
  compareWithBaseline(baselinePath) {
    console.log('🔄 Comparing with baseline...\n');

    if (!fs.existsSync(baselinePath)) {
      console.log('❌ Baseline file not found\n');
      return false;
    }

    const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
    let changes = 0;

    console.log('Changes detected:\n');

    this.criticalFiles.forEach(file => {
      const filePath = path.join(__dirname, '..', '..', file);
      const currentHash = this.calculateHash(filePath);
      const baselineHash = baseline[file];

      if (currentHash !== baselineHash) {
        console.log(`⚠️  ${file}`);
        console.log(`   Baseline: ${baselineHash || 'N/A'}`);
        console.log(`   Current:  ${currentHash || 'N/A'}\n`);
        changes++;
      }
    });

    if (changes === 0) {
      console.log('✅ No changes detected - All files match baseline\n');
    } else {
      console.log(`📊 Total changes: ${changes}\n`);
    }

    return changes === 0;
  }
}

// CLI interface
const checker = new IntegrityChecker();

const command = process.argv[2];

switch (command) {
  case 'generate':
    checker.generateChecksums();
    break;
  
  case 'verify':
    const isValid = checker.verifyIntegrity();
    process.exit(isValid ? 0 : 1);
    break;
  
  case 'watch':
    checker.watchFiles();
    // Keep process alive
    setInterval(() => {}, 1000);
    break;
  
  case 'report':
    checker.generateReport();
    break;
  
  case 'compare':
    const baselinePath = process.argv[3] || '.checksums.json';
    checker.compareWithBaseline(baselinePath);
    break;
  
  default:
    console.log('\n🔐 Nebula Shield - File Integrity Checker\n');
    console.log('Usage:');
    console.log('  node src/utils/integrityChecker.js <command>\n');
    console.log('Commands:');
    console.log('  generate  - Generate checksums for critical files');
    console.log('  verify    - Verify file integrity against checksums');
    console.log('  watch     - Watch files for changes in real-time');
    console.log('  report    - Generate detailed integrity report');
    console.log('  compare   - Compare with baseline checksums\n');
    console.log('Examples:');
    console.log('  npm run generate-checksums');
    console.log('  npm run verify-integrity');
    console.log('  npm run watch-files\n');
}

module.exports = IntegrityChecker;
