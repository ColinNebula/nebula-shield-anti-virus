#!/usr/bin/env node

/**
 * Test Script - Verify Real Protection
 * Tests all protection components
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

console.log('\n🧪 Testing Nebula Shield Real Protection\n');
console.log('═══════════════════════════════════════\n');

let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`✅ ${name}`);
        testsPassed++;
    } catch (error) {
        console.log(`❌ ${name}`);
        console.log(`   Error: ${error.message}`);
        testsFailed++;
    }
}

// Test 1: Check if chokidar is installed
test('chokidar dependency installed', () => {
    require('chokidar');
});

// Test 2: Check if all service files exist
test('real-time-file-monitor.js exists', () => {
    const exists = fs.existsSync(path.join(__dirname, 'real-time-file-monitor.js'));
    if (!exists) throw new Error('File not found');
});

test('real-process-monitor.js exists', () => {
    const exists = fs.existsSync(path.join(__dirname, 'real-process-monitor.js'));
    if (!exists) throw new Error('File not found');
});

test('cloud-threat-intelligence-manager.js exists', () => {
    const exists = fs.existsSync(path.join(__dirname, 'cloud-threat-intelligence-manager.js'));
    if (!exists) throw new Error('File not found');
});

test('integrated-protection-service.js exists', () => {
    const exists = fs.existsSync(path.join(__dirname, 'integrated-protection-service.js'));
    if (!exists) throw new Error('File not found');
});

// Test 3: Load modules without errors
test('Load real-file-scanner module', () => {
    const scanner = require('./real-file-scanner');
    if (!scanner) throw new Error('Failed to load');
});

test('Load cloud-threat-intelligence module', () => {
    const intel = require('./cloud-threat-intelligence-manager');
    if (!intel) throw new Error('Failed to load');
});

// Test 4: Check critical directories
test('Downloads directory accessible', () => {
    const downloadsPath = path.join(os.homedir(), 'Downloads');
    if (!fs.existsSync(downloadsPath)) {
        throw new Error('Downloads folder not found');
    }
});

test('Temp directory accessible', () => {
    const tempPath = os.tmpdir();
    if (!fs.existsSync(tempPath)) {
        throw new Error('Temp folder not found');
    }
});

// Test 5: Check .env configuration
test('.env.example exists', () => {
    const exists = fs.existsSync(path.join(__dirname, '.env.example'));
    if (!exists) throw new Error('.env.example not found');
});

// Test 6: Check package.json scripts
test('package.json has protection scripts', () => {
    const pkg = require('./package.json');
    if (!pkg.scripts['start:protection']) {
        throw new Error('start:protection script not found');
    }
    if (!pkg.scripts['start:all']) {
        throw new Error('start:all script not found');
    }
});

// Test 7: Check dependencies
test('systeminformation installed', () => {
    require('systeminformation');
});

test('axios installed', () => {
    require('axios');
});

test('express installed', () => {
    require('express');
});

test('cors installed', () => {
    require('cors');
});

// Summary
console.log('\n═══════════════════════════════════════\n');
console.log(`📊 Test Results:\n`);
console.log(`   ✅ Passed: ${testsPassed}`);
console.log(`   ❌ Failed: ${testsFailed}`);
console.log(`   📈 Success Rate: ${Math.round((testsPassed / (testsPassed + testsFailed)) * 100)}%\n`);

if (testsFailed === 0) {
    console.log('🎉 All tests passed! Real protection is ready.\n');
    console.log('🚀 Next steps:');
    console.log('   1. Start scanner:    npm run start:scanner');
    console.log('   2. Start protection: npm run start:protection');
    console.log('   3. Start frontend:   cd .. && npm start\n');
    process.exit(0);
} else {
    console.log('⚠️  Some tests failed. Please fix issues before starting protection.\n');
    process.exit(1);
}
