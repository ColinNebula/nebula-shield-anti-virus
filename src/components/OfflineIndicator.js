import React, { useState, useEffect } from 'react';
import { WifiOff, Wifi } from 'lucide-react';

const OfflineIndicator = () => {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [showOffline, setShowOffline] = useState(false);
  const [showReconnected, setShowReconnected] = useState(false);

  useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      setShowOffline(false);
      setShowReconnected(true);
      
      // Hide reconnected message after 3 seconds
      setTimeout(() => {
        setShowReconnected(false);
      }, 3000);
    };

    const handleOffline = () => {
      setIsOnline(false);
      setShowOffline(true);
      setShowReconnected(false);
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  if (showReconnected) {
    return (
      <div className="fixed top-4 right-4 z-50 animate-slide-down">
        <div className="bg-green-500 text-white px-4 py-3 rounded-lg shadow-lg flex items-center space-x-3">
          <Wifi className="w-5 h-5" />
          <span className="font-medium">Back online</span>
        </div>
      </div>
    );
  }

  if (!showOffline) {
    return null;
  }

  return (
    <div className="fixed top-4 right-4 z-50 animate-slide-down">
      <div className="bg-orange-500 text-white px-4 py-3 rounded-lg shadow-lg flex items-center space-x-3">
        <WifiOff className="w-5 h-5" />
        <div>
          <p className="font-medium">You're offline</p>
          <p className="text-sm text-white/90">Some features may be unavailable</p>
        </div>
      </div>
    </div>
  );
};

export default OfflineIndicator;
