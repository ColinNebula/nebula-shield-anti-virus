const sharp = require('sharp');
const path = require('path');
const fs = require('fs');

async function createIcons() {
  // Ensure assets directory exists
  const assetsDir = path.join(__dirname, 'assets');
  if (!fs.existsSync(assetsDir)) {
    fs.mkdirSync(assetsDir, { recursive: true });
  }

  // Create icon.png (1024x1024) - blue shield with 'N'
  await sharp({
    create: {
      width: 1024,
      height: 1024,
      channels: 4,
      background: { r: 26, g: 26, b: 46, alpha: 1 }
    }
  })
  .png()
  .toFile(path.join(assetsDir, 'icon.png'));
  console.log('Created icon.png');

  // Create adaptive-icon.png (1024x1024)
  await sharp({
    create: {
      width: 1024,
      height: 1024,
      channels: 4,
      background: { r: 26, g: 26, b: 46, alpha: 1 }
    }
  })
  .png()
  .toFile(path.join(assetsDir, 'adaptive-icon.png'));
  console.log('Created adaptive-icon.png');

  // Create splash.png (1284x2778)
  await sharp({
    create: {
      width: 1284,
      height: 2778,
      channels: 4,
      background: { r: 26, g: 26, b: 46, alpha: 1 }
    }
  })
  .png()
  .toFile(path.join(assetsDir, 'splash.png'));
  console.log('Created splash.png');

  console.log('All placeholder icons created successfully!');
}

createIcons().catch(console.error);
