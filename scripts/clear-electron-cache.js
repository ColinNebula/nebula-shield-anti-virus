/**
 * Clear Electron cache
 * Run this if you're seeing old logos/assets in the Electron app
 */

const fs = require('fs');
const path = require('path');

// Electron user data paths
const electronCachePaths = [
  path.join(process.env.APPDATA || process.env.HOME, 'electron'),
  path.join(process.env.LOCALAPPDATA || process.env.HOME, 'electron', 'Cache'),
  path.join(process.env.LOCALAPPDATA || process.env.HOME, 'electron', 'GPUCache'),
  path.join(process.env.LOCALAPPDATA || process.env.HOME, 'Electron'),
  path.join(process.env.TEMP || '/tmp', 'electron'),
];

function deleteDirectoryRecursive(dirPath) {
  if (fs.existsSync(dirPath)) {
    try {
      fs.rmSync(dirPath, { recursive: true, force: true });
      console.log(`✅ Cleared: ${dirPath}`);
      return true;
    } catch (error) {
      console.log(`⚠️  Could not clear ${dirPath}: ${error.message}`);
      return false;
    }
  }
  return false;
}

console.log('🧹 Clearing Electron cache...\n');

let cleared = 0;
electronCachePaths.forEach(cachePath => {
  if (deleteDirectoryRecursive(cachePath)) {
    cleared++;
  }
});

console.log(`\n✅ Cleared ${cleared} cache locations`);
console.log('📝 Also clear browser cache in Electron DevTools: Ctrl+Shift+I > Application > Clear Storage');
console.log('🔄 Restart the Electron app to see changes');
