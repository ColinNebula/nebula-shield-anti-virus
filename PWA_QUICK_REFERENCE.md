# 📱 PWA Quick Reference Card

## Installation

### Check if PWA is installable
```javascript
import { canInstallPWA, getInstallStatus } from './utils/pwaUtils';

const canInstall = canInstallPWA();
const status = getInstallStatus();
// { isPWA, canInstall, isStandalone, isIOS, isAndroid }
```

### Show Install Prompt
```javascript
import { setupInstallPrompt, showInstallPrompt } from './utils/pwaUtils';

// Setup listener
setupInstallPrompt((available) => {
  console.log('Install available:', available);
});

// Show prompt
const result = await showInstallPrompt();
// { outcome: 'accepted' | 'dismissed' | 'not-available' }
```

## Service Worker

### Register
```javascript
import { registerServiceWorker } from './utils/pwaUtils';
registerServiceWorker();
```

### Unregister
```javascript
import { unregisterServiceWorker } from './utils/pwaUtils';
await unregisterServiceWorker();
```

### Check if PWA
```javascript
import { isPWA } from './utils/pwaUtils';
const isInstalled = isPWA();
```

## Notifications

### Request Permission
```javascript
import { requestNotificationPermission } from './utils/pwaUtils';
const granted = await requestNotificationPermission();
```

### Show Notification
```javascript
import { showNotification } from './utils/pwaUtils';
showNotification('Title', {
  body: 'Message',
  icon: '/logo192.png',
  badge: '/favicon-48x48.png'
});
```

## Cache Management

### Clear Cache
```javascript
import { clearCache } from './utils/pwaUtils';
await clearCache();
```

### Get Cache Size
```javascript
import { getCacheSize } from './utils/pwaUtils';
const size = await getCacheSize();
// { usage, quota, usageInMB, quotaInMB, percentUsed }
```

## Network Status

### Check Online Status
```javascript
import { isOnline } from './utils/pwaUtils';
const online = isOnline();
```

### Listen for Changes
```javascript
import { setupOnlineListeners } from './utils/pwaUtils';
setupOnlineListeners(
  () => console.log('Online'),
  () => console.log('Offline')
);
```

## Sharing

### Check Share Support
```javascript
import { canShare } from './utils/pwaUtils';
const supported = canShare();
```

### Share Content
```javascript
import { shareContent } from './utils/pwaUtils';
const result = await shareContent({
  title: 'Title',
  text: 'Description',
  url: 'https://example.com'
});
// { success: boolean, error?: string }
```

## Components

### Install Prompt
```javascript
import PWAInstallPrompt from './components/PWAInstallPrompt';
<PWAInstallPrompt />
```

### Offline Indicator
```javascript
import OfflineIndicator from './components/OfflineIndicator';
<OfflineIndicator />
```

## Service Worker Events

### Update Cache Version
```javascript
// In public/service-worker.js
const CACHE_NAME = 'nebula-shield-v1.0.1'; // Increment
```

### Send Message to SW
```javascript
navigator.serviceWorker.controller.postMessage({
  type: 'SKIP_WAITING'
});
```

### Clear Cache via SW
```javascript
navigator.serviceWorker.controller.postMessage({
  type: 'CLEAR_CACHE'
});
```

## Debugging

### Chrome DevTools
1. F12 → Application tab
2. Check Service Workers
3. Check Manifest
4. Check Cache Storage

### Test Installation
- DevTools → Application → Manifest → "Add to home screen"

### Lighthouse Audit
- DevTools → Lighthouse → PWA category

## Platform Detection

```javascript
import { isIOSSafari } from './utils/pwaUtils';
const needsManualInstall = isIOSSafari();
```

## Build Considerations

- Service Worker in `public/` folder
- Manifest icons: 16, 32, 48, 192, 512
- HTTPS required (or localhost)
- Update cache version on deploy
