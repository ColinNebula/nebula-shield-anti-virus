import React, { useState, useEffect } from 'react';
import { 
  Smartphone, 
  Download, 
  Wifi, 
  WifiOff, 
  Bell, 
  BellOff, 
  Trash2,
  HardDrive,
  Share2,
  RefreshCw
} from 'lucide-react';
import {
  isPWA,
  getInstallStatus,
  showInstallPrompt,
  requestNotificationPermission,
  clearCache,
  getCacheSize,
  isOnline,
  canShare,
  shareContent,
  unregisterServiceWorker
} from '../utils/pwaUtils';

const PWASettings = () => {
  const [installStatus, setInstallStatus] = useState({});
  const [cacheSize, setCacheSize] = useState(null);
  const [notificationPermission, setNotificationPermission] = useState('default');
  const [online, setOnline] = useState(navigator.onLine);
  const [loading, setLoading] = useState({});

  useEffect(() => {
    loadPWAStatus();

    // Listen for online/offline events
    const handleOnline = () => setOnline(true);
    const handleOffline = () => setOnline(false);
    
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  const loadPWAStatus = async () => {
    const status = getInstallStatus();
    setInstallStatus(status);

    const size = await getCacheSize();
    setCacheSize(size);

    if ('Notification' in window) {
      setNotificationPermission(Notification.permission);
    }
  };

  const handleInstallApp = async () => {
    setLoading({ ...loading, install: true });
    const result = await showInstallPrompt();
    if (result.outcome === 'accepted') {
      await loadPWAStatus();
    }
    setLoading({ ...loading, install: false });
  };

  const handleEnableNotifications = async () => {
    setLoading({ ...loading, notifications: true });
    const granted = await requestNotificationPermission();
    setNotificationPermission(granted ? 'granted' : 'denied');
    setLoading({ ...loading, notifications: false });
  };

  const handleClearCache = async () => {
    if (!window.confirm('Clear all cached data? This will reload the page.')) {
      return;
    }

    setLoading({ ...loading, cache: true });
    await clearCache();
    
    // Unregister service worker
    await unregisterServiceWorker();
    
    // Reload the page
    window.location.reload();
  };

  const handleShareApp = async () => {
    if (canShare()) {
      await shareContent({
        title: 'Nebula Shield Anti-Virus',
        text: 'Advanced security protection for your device',
        url: window.location.origin
      });
    }
  };

  const handleRefreshCache = () => {
    if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
      navigator.serviceWorker.controller.postMessage({
        type: 'CLEAR_CACHE'
      });
      setTimeout(() => {
        window.location.reload();
      }, 500);
    }
  };

  return (
    <div className="pwa-settings space-y-6">
      <div className="card">
        <h3 className="text-xl font-bold mb-4 flex items-center">
          <Smartphone className="w-5 h-5 mr-2" />
          Progressive Web App (PWA)
        </h3>

        {/* Installation Status */}
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg">
            <div className="flex items-center space-x-3">
              {installStatus.isPWA ? (
                <>
                  <div className="w-10 h-10 rounded-full bg-green-500/20 flex items-center justify-center">
                    <Smartphone className="w-5 h-5 text-green-500" />
                  </div>
                  <div>
                    <p className="font-medium">Installed as App</p>
                    <p className="text-sm text-gray-400">Running in standalone mode</p>
                  </div>
                </>
              ) : (
                <>
                  <div className="w-10 h-10 rounded-full bg-blue-500/20 flex items-center justify-center">
                    <Download className="w-5 h-5 text-blue-500" />
                  </div>
                  <div>
                    <p className="font-medium">Install Available</p>
                    <p className="text-sm text-gray-400">Add to home screen for quick access</p>
                  </div>
                </>
              )}
            </div>
            
            {!installStatus.isPWA && installStatus.canInstall && (
              <button
                onClick={handleInstallApp}
                disabled={loading.install}
                className="btn btn-primary flex items-center space-x-2"
              >
                <Download className="w-4 h-4" />
                <span>Install</span>
              </button>
            )}
          </div>

          {/* Network Status */}
          <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg">
            <div className="flex items-center space-x-3">
              <div className={`w-10 h-10 rounded-full ${online ? 'bg-green-500/20' : 'bg-orange-500/20'} flex items-center justify-center`}>
                {online ? (
                  <Wifi className="w-5 h-5 text-green-500" />
                ) : (
                  <WifiOff className="w-5 h-5 text-orange-500" />
                )}
              </div>
              <div>
                <p className="font-medium">{online ? 'Online' : 'Offline'}</p>
                <p className="text-sm text-gray-400">
                  {online ? 'Connected to network' : 'Working in offline mode'}
                </p>
              </div>
            </div>
            <div className={`w-3 h-3 rounded-full ${online ? 'bg-green-500' : 'bg-orange-500'}`} />
          </div>

          {/* Notifications */}
          <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg">
            <div className="flex items-center space-x-3">
              <div className={`w-10 h-10 rounded-full ${notificationPermission === 'granted' ? 'bg-green-500/20' : 'bg-gray-500/20'} flex items-center justify-center`}>
                {notificationPermission === 'granted' ? (
                  <Bell className="w-5 h-5 text-green-500" />
                ) : (
                  <BellOff className="w-5 h-5 text-gray-400" />
                )}
              </div>
              <div>
                <p className="font-medium">Push Notifications</p>
                <p className="text-sm text-gray-400">
                  {notificationPermission === 'granted' ? 'Enabled' : 'Disabled'}
                </p>
              </div>
            </div>
            
            {notificationPermission !== 'granted' && (
              <button
                onClick={handleEnableNotifications}
                disabled={loading.notifications || notificationPermission === 'denied'}
                className="btn btn-secondary flex items-center space-x-2"
              >
                <Bell className="w-4 h-4" />
                <span>Enable</span>
              </button>
            )}
          </div>

          {/* Cache Info */}
          {cacheSize && (
            <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-full bg-purple-500/20 flex items-center justify-center">
                  <HardDrive className="w-5 h-5 text-purple-500" />
                </div>
                <div>
                  <p className="font-medium">Cache Storage</p>
                  <p className="text-sm text-gray-400">
                    {cacheSize.usageInMB} MB / {cacheSize.quotaInMB} MB ({cacheSize.percentUsed}%)
                  </p>
                </div>
              </div>
              
              <div className="flex space-x-2">
                <button
                  onClick={handleRefreshCache}
                  className="btn btn-secondary flex items-center space-x-2"
                  title="Refresh cache"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
                <button
                  onClick={handleClearCache}
                  disabled={loading.cache}
                  className="btn btn-danger flex items-center space-x-2"
                >
                  <Trash2 className="w-4 h-4" />
                  <span>Clear</span>
                </button>
              </div>
            </div>
          )}

          {/* Share App */}
          {canShare() && (
            <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-full bg-blue-500/20 flex items-center justify-center">
                  <Share2 className="w-5 h-5 text-blue-500" />
                </div>
                <div>
                  <p className="font-medium">Share App</p>
                  <p className="text-sm text-gray-400">Share with friends and family</p>
                </div>
              </div>
              
              <button
                onClick={handleShareApp}
                className="btn btn-secondary flex items-center space-x-2"
              >
                <Share2 className="w-4 h-4" />
                <span>Share</span>
              </button>
            </div>
          )}
        </div>

        {/* Device Info */}
        {(installStatus.isIOS || installStatus.isAndroid) && (
          <div className="mt-4 p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
            <p className="text-sm text-blue-400">
              <strong>Platform:</strong> {installStatus.isIOS ? 'iOS' : 'Android'}
              {installStatus.isIOS && !installStatus.isPWA && (
                <span className="block mt-2">
                  To install: Tap Share → Add to Home Screen
                </span>
              )}
            </p>
          </div>
        )}
      </div>

      {/* PWA Features Info */}
      <div className="card">
        <h4 className="font-semibold mb-3">PWA Benefits</h4>
        <ul className="space-y-2 text-sm text-gray-400">
          <li className="flex items-start">
            <span className="text-green-500 mr-2">✓</span>
            <span>Works offline with cached content</span>
          </li>
          <li className="flex items-start">
            <span className="text-green-500 mr-2">✓</span>
            <span>Faster load times with service worker</span>
          </li>
          <li className="flex items-start">
            <span className="text-green-500 mr-2">✓</span>
            <span>Native app-like experience</span>
          </li>
          <li className="flex items-start">
            <span className="text-green-500 mr-2">✓</span>
            <span>Push notifications for important alerts</span>
          </li>
          <li className="flex items-start">
            <span className="text-green-500 mr-2">✓</span>
            <span>Reduced data usage with caching</span>
          </li>
          <li className="flex items-start">
            <span className="text-green-500 mr-2">✓</span>
            <span>Quick access from home screen</span>
          </li>
        </ul>
      </div>
    </div>
  );
};

export default PWASettings;
