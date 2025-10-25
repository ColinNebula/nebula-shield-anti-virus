/**
 * Create favicon.ico for the public folder
 */

const pngToIco = require('png-to-ico').default || require('png-to-ico');
const fs = require('fs');
const path = require('path');

async function createFavicon() {
  const pngFiles = [16, 32, 48].map(size => 
    path.join(__dirname, `icon-${size}x${size}.png`)
  );

  const ico = await pngToIco(pngFiles);
  fs.writeFileSync(path.join(__dirname, '..', 'public', 'favicon.ico'), ico);
  console.log('✅ Created public/favicon.ico');
}

createFavicon().catch(console.error);
