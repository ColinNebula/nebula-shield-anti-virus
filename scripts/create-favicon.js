/**
 * Create favicon.ico from logo.svg
 */

const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

async function createFavicon() {
  try {
    const svgPath = path.join(__dirname, '..', 'public', 'logo.svg');
    const svgBuffer = fs.readFileSync(svgPath);
    
    // Create 32x32 PNG for favicon
    const pngBuffer = await sharp(svgBuffer)
      .resize(32, 32)
      .png()
      .toBuffer();
    
    // Save as PNG (ICO format is complex, so we'll use PNG)
    // Modern browsers support PNG favicons
    await sharp(pngBuffer)
      .toFile(path.join(__dirname, '..', 'public', 'favicon.png'));
    
    console.log('✅ Created favicon.png (32x32)');
    
    // Also create a 16x16 version
    await sharp(svgBuffer)
      .resize(16, 16)
      .png()
      .toFile(path.join(__dirname, '..', 'public', 'favicon-16x16.png'));
    
    console.log('✅ Created favicon-16x16.png (16x16)');
    console.log('🎉 Favicon generated successfully!');
    console.log('📝 Note: Update index.html to use favicon.png instead of favicon.ico');
    
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

createFavicon();
