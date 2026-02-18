const { getDefaultConfig } = require('expo/metro-config');
const path = require('path');

const config = getDefaultConfig(__dirname);

// Ensure Metro only watches the mobile directory
config.watchFolders = [__dirname];

// Exclude parent directory files (like electron.js)
config.resolver = {
  ...config.resolver,
  blockList: [
    /\.\.\/public\/.*/,
    /\.\.\/build\/.*/,
    /\.\.\/dist\/.*/,
    /\.\.\/electron\/.*/,
    /public\/electron\.js/,
  ],
};

module.exports = config;
