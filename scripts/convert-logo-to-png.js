/**
 * Convert Nebula Shield SVG logo to PNG format
 * Creates logo192.png and logo512.png
 */

const fs = require('fs');
const path = require('path');

// Simple PNG creator using Canvas (if available) or fallback
async function convertSvgToPng() {
  try {
    // Try using sharp package if available
    const sharp = require('sharp');
    
    const svgPath = path.join(__dirname, '..', 'public', 'logo.svg');
    const svgBuffer = fs.readFileSync(svgPath);
    
    // Create 192x192 PNG
    await sharp(svgBuffer)
      .resize(192, 192)
      .png()
      .toFile(path.join(__dirname, '..', 'public', 'logo192.png'));
    
    console.log('✅ Created logo192.png (192x192)');
    
    // Create 512x512 PNG
    await sharp(svgBuffer)
      .resize(512, 512)
      .png()
      .toFile(path.join(__dirname, '..', 'public', 'logo512.png'));
    
    console.log('✅ Created logo512.png (512x512)');
    console.log('🎉 PNG logos generated successfully!');
    
  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.log('📦 Installing sharp package...');
      console.log('Run: npm install sharp --save-dev');
      console.log('Then run this script again: node scripts/convert-logo-to-png.js');
      process.exit(1);
    } else {
      console.error('❌ Error:', error.message);
      process.exit(1);
    }
  }
}

convertSvgToPng();
