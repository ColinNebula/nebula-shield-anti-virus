const fs = require('fs');
const path = require('path');
const os = require('os');

const cacheDirs = [
  // Electron cache directories
  path.join(os.homedir(), 'AppData', 'Local', 'electron', 'Cache'),
  path.join(os.homedir(), 'AppData', 'Local', 'Electron'),
  path.join(os.homedir(), 'AppData', 'Local', 'electron', 'GPUCache'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'electron'),
  
  // App-specific cache
  path.join(os.homedir(), 'AppData', 'Local', 'nebula-shield-anti-virus'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'nebula-shield-anti-virus'),
  
  // Service Worker cache
  path.join(__dirname, '..', 'build', 'service-worker.js'),
  
  // Node modules cache
  path.join(__dirname, '..', 'node_modules', '.cache')
];

console.log('🧹 Force clearing all Electron and app caches...\n');

let cleared = 0;
cacheDirs.forEach(dirPath => {
  try {
    if (fs.existsSync(dirPath)) {
      fs.rmSync(dirPath, { recursive: true, force: true });
      console.log(`✅ Cleared: ${dirPath}`);
      cleared++;
    } else {
      console.log(`⏭️  Skipped (not found): ${dirPath}`);
    }
  } catch (error) {
    console.log(`❌ Failed to clear ${dirPath}: ${error.message}`);
  }
});

console.log(`\n✅ Cleared ${cleared} cache locations\n`);

// Also clear any cached webpack builds
const webpackCache = path.join(__dirname, '..', 'node_modules', '.cache', 'webpack');
if (fs.existsSync(webpackCache)) {
  try {
    fs.rmSync(webpackCache, { recursive: true, force: true });
    console.log('✅ Cleared webpack cache');
  } catch (error) {
    console.log('❌ Failed to clear webpack cache:', error.message);
  }
}

console.log('\n🔄 Next steps:');
console.log('1. Restart the Electron app: npm run electron:dev');
console.log('2. In the app, press Ctrl+Shift+I to open DevTools');
console.log('3. Go to Application > Storage > Clear site data');
console.log('4. Press Ctrl+Shift+R to hard refresh\n');
