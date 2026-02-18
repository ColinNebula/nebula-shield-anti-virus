#!/usr/bin/env node

const axios = require('axios');

const AUTH_BASE = process.env.AUTH_API_BASE || 'http://localhost:8082';

async function run() {
  try {
    const response = await axios.get(`${AUTH_BASE}/api/platform/antivirus`, {
      timeout: 8000
    });

    const antivirus = response.data?.antivirus || {};
    const available = antivirus.available === true;
    const enabled = antivirus.enabled === true;

    console.log('AV status response:', antivirus);

    if (!available) {
      console.log('✅ No AV installed flow OK (available=false).');
    } else if (!enabled) {
      console.log('⚠️  AV detected but disabled (enabled=false).');
    } else {
      console.log('✅ AV detected and enabled.');
    }

    process.exit(0);
  } catch (error) {
    const status = error.response?.status;
    const data = error.response?.data;
    console.error('❌ Failed to fetch AV status:', status || error.message, data || '');
    process.exit(1);
  }
}

run();
