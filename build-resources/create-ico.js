/**
 * Create Windows ICO file from PNG files
 * ICO format supports multiple sizes in one file
 */

const pngToIco = require('png-to-ico').default || require('png-to-ico');
const fs = require('fs');
const path = require('path');

const buildResourcesDir = __dirname;
const outputIco = path.join(buildResourcesDir, 'icon.ico');

// Standard Windows icon sizes
const iconSizes = [16, 32, 48, 64, 128, 256];

async function createIco() {
  console.log('🎨 Creating Windows ICO file...\n');

  const pngFiles = iconSizes.map(size => 
    path.join(buildResourcesDir, `icon-${size}x${size}.png`)
  );

  // Check if all PNG files exist
  for (const file of pngFiles) {
    if (!fs.existsSync(file)) {
      console.error(`❌ Missing PNG file: ${path.basename(file)}`);
      console.error('   Run: node build-resources/generate-icons.js first');
      process.exit(1);
    }
  }

  console.log('📦 Combining PNG files into ICO...');
  iconSizes.forEach(size => {
    console.log(`  ✓ Including ${size}x${size}`);
  });

  try {
    const icoBuffer = await pngToIco(pngFiles);
    fs.writeFileSync(outputIco, icoBuffer);
    
    const fileSize = (fs.statSync(outputIco).size / 1024).toFixed(2);
    console.log(`\n✅ Created icon.ico (${fileSize} KB)`);
    console.log(`   Location: ${outputIco}`);
    console.log('\n📋 Next steps:');
    console.log('   1. Rebuild Electron app: npm run electron:build:win');
    console.log('   2. The new icon will be used for the executable and taskbar');
  } catch (error) {
    console.error('❌ Error creating ICO:', error);
    process.exit(1);
  }
}

createIco();
