/**
 * Nebula Shield Icon Generator - All-in-One
 * Generates all icons needed for the application from the SVG source
 * 
 * Usage: npm run generate-icons
 */

const fs = require('fs');
const path = require('path');

// Check for dependencies
let sharp, pngToIco;
try {
  sharp = require('sharp');
  pngToIco = require('png-to-ico').default || require('png-to-ico');
} catch (e) {
  console.error('❌ Missing dependencies!');
  console.error('   Run: npm install --save-dev sharp png-to-ico');
  process.exit(1);
}

const svgPath = path.join(__dirname, 'icon.svg');
const buildResourcesDir = __dirname;
const publicDir = path.join(__dirname, '..', 'public');

const sizes = {
  icons: [16, 24, 32, 48, 64, 96, 128, 192, 256, 512, 1024],
  ico: [16, 32, 48, 64, 128, 256],
  favicon: [16, 32, 48],
  pwa: [192, 512]
};

async function generateAllIcons() {
  console.log('🎨 Nebula Shield Icon Generator\n');
  console.log('━'.repeat(50));

  if (!fs.existsSync(svgPath)) {
    console.error('❌ icon.svg not found!');
    process.exit(1);
  }

  const svgBuffer = fs.readFileSync(svgPath);

  // Step 1: Generate all PNG sizes
  console.log('\n📦 Step 1: Generating PNG icons...');
  for (const size of sizes.icons) {
    const outputPath = path.join(buildResourcesDir, `icon-${size}x${size}.png`);
    await sharp(svgBuffer)
      .resize(size, size, {
        fit: 'contain',
        background: { r: 0, g: 0, b: 0, alpha: 0 }
      })
      .png({ quality: 100, compressionLevel: 9 })
      .toFile(outputPath);
    console.log(`  ✓ ${size}x${size}`);
  }

  // Step 2: Generate main icon.png (1024x1024)
  console.log('\n📦 Step 2: Generating main icon.png...');
  const mainIconPath = path.join(buildResourcesDir, 'icon.png');
  await sharp(svgBuffer)
    .resize(1024, 1024, {
      fit: 'contain',
      background: { r: 0, g: 0, b: 0, alpha: 0 }
    })
    .png({ quality: 100, compressionLevel: 9 })
    .toFile(mainIconPath);
  console.log('  ✓ icon.png (1024x1024)');

  // Step 3: Generate Windows ICO
  console.log('\n📦 Step 3: Generating Windows ICO...');
  const icoPngFiles = sizes.ico.map(size => 
    path.join(buildResourcesDir, `icon-${size}x${size}.png`)
  );
  const icoBuffer = await pngToIco(icoPngFiles);
  fs.writeFileSync(path.join(buildResourcesDir, 'icon.ico'), icoBuffer);
  const icoSize = (icoBuffer.length / 1024).toFixed(2);
  console.log(`  ✓ icon.ico (${icoSize} KB with ${sizes.ico.length} sizes)`);

  // Step 4: Generate public folder icons
  console.log('\n📦 Step 4: Generating public folder icons...');
  
  // Favicon ICO
  const faviconPngFiles = sizes.favicon.map(size => 
    path.join(buildResourcesDir, `icon-${size}x${size}.png`)
  );
  const faviconBuffer = await pngToIco(faviconPngFiles);
  fs.writeFileSync(path.join(publicDir, 'favicon.ico'), faviconBuffer);
  console.log('  ✓ favicon.ico');

  // High-res PNG for Electron window
  fs.copyFileSync(
    path.join(buildResourcesDir, 'icon-256x256.png'),
    path.join(publicDir, 'icon.png')
  );
  console.log('  ✓ icon.png (256x256 for Electron)');

  // PWA icons
  for (const size of sizes.pwa) {
    fs.copyFileSync(
      path.join(buildResourcesDir, `icon-${size}x${size}.png`),
      path.join(publicDir, `logo${size}.png`)
    );
    console.log(`  ✓ logo${size}.png`);
  }

  // Individual favicon sizes
  for (const size of [16, 32]) {
    fs.copyFileSync(
      path.join(buildResourcesDir, `icon-${size}x${size}.png`),
      path.join(publicDir, `favicon-${size}x${size}.png`)
    );
  }
  console.log('  ✓ favicon-16x16.png, favicon-32x32.png');

  console.log('\n━'.repeat(50));
  console.log('✅ All icons generated successfully!');
  console.log('\n📋 Generated files:');
  console.log('   • build-resources/icon.ico (Windows executable)');
  console.log('   • build-resources/icon.png (1024x1024 main icon)');
  console.log('   • build-resources/icon-*x*.png (11 PNG sizes)');
  console.log('   • public/favicon.ico (browser favicon)');
  console.log('   • public/icon.png (Electron window icon)');
  console.log('   • public/logo192.png, logo512.png (PWA icons)');
  console.log('\n🚀 Next step: npm run electron:build:win');
}

generateAllIcons().catch(err => {
  console.error('\n❌ Error generating icons:', err);
  process.exit(1);
});
