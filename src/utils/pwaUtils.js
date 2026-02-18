// PWA Utilities for Nebula Shield

/**
 * Register service worker for PWA functionality
 */
export const registerServiceWorker = () => {
  // Skip service worker in Electron (uses file:// protocol)
  if (window.electronAPI || window.location.protocol === 'file:') {
    console.log('⚠️ Service Worker skipped - running in Electron');
    return;
  }
  
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker
        .register('/service-worker.js')
        .then((registration) => {
          console.log('✅ Service Worker registered successfully:', registration.scope);

          // Check for updates periodically
          setInterval(() => {
            registration.update();
          }, 60000); // Check every minute

          // Handle updates
          registration.addEventListener('updatefound', () => {
            const newWorker = registration.installing;
            
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                // New service worker available
                console.log('🔄 New version available! Please refresh.');
                
                // Notify user about update
                if (window.confirm('A new version of Nebula Shield is available. Refresh to update?')) {
                  newWorker.postMessage({ type: 'SKIP_WAITING' });
                  window.location.reload();
                }
              }
            });
          });
        })
        .catch((error) => {
          console.error('❌ Service Worker registration failed:', error);
        });

      // Handle controller change
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        console.log('🔄 Service Worker controller changed');
      });
    });
  } else {
    console.log('⚠️ Service Workers not supported in this browser');
  }
};

/**
 * Unregister service worker
 */
export const unregisterServiceWorker = async () => {
  if ('serviceWorker' in navigator) {
    try {
      const registrations = await navigator.serviceWorker.getRegistrations();
      for (const registration of registrations) {
        await registration.unregister();
      }
      console.log('✅ Service Worker unregistered');
      return true;
    } catch (error) {
      console.error('❌ Service Worker unregistration failed:', error);
      return false;
    }
  }
  return false;
};

/**
 * Check if app is running as PWA
 */
export const isPWA = () => {
  return (
    window.matchMedia('(display-mode: standalone)').matches ||
    window.navigator.standalone === true ||
    document.referrer.includes('android-app://')
  );
};

/**
 * Check if PWA installation is supported
 */
export const canInstallPWA = () => {
  return 'BeforeInstallPromptEvent' in window || isPWA();
};

/**
 * Get PWA install prompt
 */
let deferredPrompt = null;

export const setupInstallPrompt = (callback) => {
  window.addEventListener('beforeinstallprompt', (e) => {
    // Prevent the mini-infobar from appearing on mobile
    e.preventDefault();
    // Stash the event so it can be triggered later
    deferredPrompt = e;
    
    console.log('📱 PWA install prompt available');
    
    // Notify the callback that install is available
    if (callback) {
      callback(true);
    }
  });

  window.addEventListener('appinstalled', () => {
    console.log('✅ PWA installed successfully');
    deferredPrompt = null;
    
    // Track installation
    if (window.gtag) {
      window.gtag('event', 'pwa_install', {
        event_category: 'engagement',
        event_label: 'PWA Installation'
      });
    }
  });
};

/**
 * Show PWA install prompt
 */
export const showInstallPrompt = async () => {
  if (!deferredPrompt) {
    return { outcome: 'not-available' };
  }

  // Show the install prompt
  deferredPrompt.prompt();

  // Wait for the user to respond to the prompt
  const { outcome } = await deferredPrompt.userChoice;
  
  console.log(`User response to install prompt: ${outcome}`);

  // Clear the deferredPrompt for next time
  deferredPrompt = null;

  return { outcome };
};

/**
 * Get installation status
 */
export const getInstallStatus = () => {
  return {
    isPWA: isPWA(),
    canInstall: deferredPrompt !== null,
    isStandalone: window.matchMedia('(display-mode: standalone)').matches,
    isIOS: /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream,
    isAndroid: /Android/.test(navigator.userAgent),
  };
};

/**
 * Check for iOS Safari (requires manual Add to Home Screen)
 */
export const isIOSSafari = () => {
  const ua = window.navigator.userAgent;
  const iOS = /iPad|iPhone|iPod/.test(ua);
  const webkit = /WebKit/.test(ua);
  const iOSSafari = iOS && webkit && !/CriOS|FxiOS|OPiOS|mercury/.test(ua);
  return iOSSafari && !isPWA();
};

/**
 * Request notification permission
 */
export const requestNotificationPermission = async () => {
  if (!('Notification' in window)) {
    console.log('⚠️ This browser does not support notifications');
    return false;
  }

  if (Notification.permission === 'granted') {
    return true;
  }

  if (Notification.permission !== 'denied') {
    const permission = await Notification.requestPermission();
    return permission === 'granted';
  }

  return false;
};

/**
 * Show notification
 */
export const showNotification = (title, options = {}) => {
  if (Notification.permission === 'granted') {
    if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
      // Use service worker to show notification
      navigator.serviceWorker.ready.then((registration) => {
        registration.showNotification(title, {
          icon: '/logo192.png',
          badge: '/favicon-48x48.png',
          ...options,
        });
      });
    } else {
      // Fallback to regular notification
      new Notification(title, {
        icon: '/logo192.png',
        ...options,
      });
    }
  }
};

/**
 * Cache management
 */
export const clearCache = async () => {
  if ('caches' in window) {
    const cacheNames = await caches.keys();
    await Promise.all(cacheNames.map((name) => caches.delete(name)));
    console.log('✅ Cache cleared');
    return true;
  }
  return false;
};

/**
 * Get cache size
 */
export const getCacheSize = async () => {
  if ('caches' in window && 'storage' in navigator && 'estimate' in navigator.storage) {
    const estimate = await navigator.storage.estimate();
    return {
      usage: estimate.usage,
      quota: estimate.quota,
      usageInMB: (estimate.usage / (1024 * 1024)).toFixed(2),
      quotaInMB: (estimate.quota / (1024 * 1024)).toFixed(2),
      percentUsed: ((estimate.usage / estimate.quota) * 100).toFixed(2),
    };
  }
  return null;
};

/**
 * Check if online
 */
export const isOnline = () => {
  return navigator.onLine;
};

/**
 * Setup online/offline listeners
 */
export const setupOnlineListeners = (onOnline, onOffline) => {
  window.addEventListener('online', () => {
    console.log('🌐 Back online');
    if (onOnline) onOnline();
  });

  window.addEventListener('offline', () => {
    console.log('📡 Connection lost');
    if (onOffline) onOffline();
  });
};

/**
 * Share API support
 */
export const canShare = () => {
  return 'share' in navigator;
};

/**
 * Share content
 */
export const shareContent = async (data) => {
  if (!canShare()) {
    return { success: false, error: 'Share API not supported' };
  }

  try {
    await navigator.share(data);
    return { success: true };
  } catch (error) {
    if (error.name !== 'AbortError') {
      console.error('Error sharing:', error);
      return { success: false, error: error.message };
    }
    return { success: false, error: 'Share cancelled' };
  }
};

export default {
  registerServiceWorker,
  unregisterServiceWorker,
  isPWA,
  canInstallPWA,
  setupInstallPrompt,
  showInstallPrompt,
  getInstallStatus,
  isIOSSafari,
  requestNotificationPermission,
  showNotification,
  clearCache,
  getCacheSize,
  isOnline,
  setupOnlineListeners,
  canShare,
  shareContent,
};
