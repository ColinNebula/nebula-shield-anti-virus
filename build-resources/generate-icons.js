/**
 * Generate High-Quality Icons for Nebula Shield Anti-Virus
 * Converts SVG to multiple PNG sizes and ICO format
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Check if sharp is installed
let sharp;
try {
  sharp = require('sharp');
  console.log('✓ Using sharp for high-quality image processing');
} catch (e) {
  console.log('⚠ sharp not found, installing...');
  console.log('Run: npm install --save-dev sharp');
  process.exit(1);
}

const sizes = {
  windows: [16, 32, 48, 64, 128, 256, 512, 1024],
  mac: [16, 32, 64, 128, 256, 512, 1024],
  png: [16, 24, 32, 48, 64, 96, 128, 192, 256, 512, 1024]
};

const svgPath = path.join(__dirname, 'icon.svg');
const outputDir = __dirname;

async function generateIcons() {
  console.log('🎨 Generating Nebula Shield Icons...\n');

  if (!fs.existsSync(svgPath)) {
    console.error('❌ icon.svg not found!');
    process.exit(1);
  }

  // Read SVG
  const svgBuffer = fs.readFileSync(svgPath);

  // Generate PNG icons at various sizes
  console.log('📦 Generating PNG icons...');
  
  for (const size of sizes.png) {
    const outputPath = path.join(outputDir, `icon-${size}x${size}.png`);
    
    await sharp(svgBuffer)
      .resize(size, size, {
        fit: 'contain',
        background: { r: 0, g: 0, b: 0, alpha: 0 }
      })
      .png({ quality: 100, compressionLevel: 9 })
      .toFile(outputPath);
    
    console.log(`  ✓ Generated ${size}x${size} PNG`);
  }

  // Generate main icon.png (1024x1024 for best quality)
  console.log('\n📦 Generating main icon.png (1024x1024)...');
  const mainIconPath = path.join(outputDir, 'icon.png');
  await sharp(svgBuffer)
    .resize(1024, 1024, {
      fit: 'contain',
      background: { r: 0, g: 0, b: 0, alpha: 0 }
    })
    .png({ quality: 100, compressionLevel: 9 })
    .toFile(mainIconPath);
  console.log('  ✓ Generated icon.png');

  // Generate public folder icons
  console.log('\n📦 Generating public folder icons...');
  const publicDir = path.join(__dirname, '..', 'public');
  
  // favicon.ico sizes (16, 32, 48)
  for (const size of [16, 32, 48]) {
    const outputPath = path.join(publicDir, `favicon-${size}x${size}.png`);
    await sharp(svgBuffer)
      .resize(size, size, {
        fit: 'contain',
        background: { r: 0, g: 0, b: 0, alpha: 0 }
      })
      .png({ quality: 100 })
      .toFile(outputPath);
    console.log(`  ✓ Generated favicon-${size}x${size}.png`);
  }

  // logo192.png and logo512.png for PWA
  for (const size of [192, 512]) {
    const outputPath = path.join(publicDir, `logo${size}.png`);
    await sharp(svgBuffer)
      .resize(size, size, {
        fit: 'contain',
        background: { r: 0, g: 0, b: 0, alpha: 0 }
      })
      .png({ quality: 100 })
      .toFile(outputPath);
    console.log(`  ✓ Generated logo${size}.png`);
  }

  console.log('\n✅ Icon generation complete!');
  console.log('\n📋 Next steps:');
  console.log('   1. Use png-to-ico or electron-builder to create icon.ico from the PNG files');
  console.log('   2. For macOS, use iconutil to create icon.icns');
  console.log('   3. Rebuild the Electron app: npm run electron:build:win');
}

// Check if sharp is available
if (sharp) {
  generateIcons().catch(err => {
    console.error('❌ Error generating icons:', err);
    process.exit(1);
  });
}
