import React, { useState, useEffect } from 'react';
import { X, Download, Share2, Smartphone, Monitor } from 'lucide-react';
import { 
  setupInstallPrompt, 
  showInstallPrompt, 
  getInstallStatus,
  isIOSSafari 
} from '../utils/pwaUtils';
import './PWAInstallPrompt.css';

const PWAInstallPrompt = () => {
  const [showPrompt, setShowPrompt] = useState(false);
  const [installStatus, setInstallStatus] = useState({});
  const [showIOSInstructions, setShowIOSInstructions] = useState(false);

  useEffect(() => {
    // Setup install prompt listener
    setupInstallPrompt((available) => {
      setShowPrompt(available);
    });

    // Check installation status
    const status = getInstallStatus();
    setInstallStatus(status);

    // Show iOS instructions if applicable
    if (isIOSSafari()) {
      setShowIOSInstructions(true);
    }

    // Don't show prompt if already installed
    if (status.isPWA) {
      setShowPrompt(false);
    }
  }, []);

  const handleInstall = async () => {
    const result = await showInstallPrompt();
    
    if (result.outcome === 'accepted') {
      setShowPrompt(false);
    }
  };

  const handleDismiss = () => {
    setShowPrompt(false);
    // Remember dismissal for 7 days
    localStorage.setItem('pwa-install-dismissed', Date.now().toString());
  };

  const handleDismissIOS = () => {
    setShowIOSInstructions(false);
    localStorage.setItem('pwa-ios-dismissed', Date.now().toString());
  };

  // Check if dismissed recently
  useEffect(() => {
    const dismissed = localStorage.getItem('pwa-install-dismissed');
    if (dismissed) {
      const dismissedTime = parseInt(dismissed);
      const sevenDays = 7 * 24 * 60 * 60 * 1000;
      if (Date.now() - dismissedTime < sevenDays) {
        setShowPrompt(false);
      }
    }

    const iosDismissed = localStorage.getItem('pwa-ios-dismissed');
    if (iosDismissed) {
      const dismissedTime = parseInt(iosDismissed);
      const sevenDays = 7 * 24 * 60 * 60 * 1000;
      if (Date.now() - dismissedTime < sevenDays) {
        setShowIOSInstructions(false);
      }
    }
  }, []);

  // Don't show if already installed
  if (installStatus.isPWA) {
    return null;
  }

  // iOS Safari Instructions
  if (showIOSInstructions) {
    return (
      <div className="pwa-install-prompt">
        <div className="pwa-prompt-card">
          <div className="pwa-prompt-bg-circle"></div>
          <div className="pwa-prompt-bg-glow"></div>
          
          <button
            onClick={handleDismissIOS}
            className="pwa-close-btn"
            aria-label="Dismiss"
          >
            <X className="w-4 h-4" />
          </button>
          
          <div className="pwa-prompt-header">
            <div className="pwa-icon-container">
              <Smartphone />
            </div>
            <div className="pwa-prompt-text">
              <h3 className="pwa-prompt-title">Install Nebula Shield</h3>
              <p className="pwa-prompt-description">
                Add to your home screen for quick access:
              </p>
            </div>
          </div>

          <div className="pwa-ios-instructions">
            <ol className="pwa-ios-list">
              <li className="pwa-ios-step">
                <span className="pwa-step-number">1.</span>
                <span>Tap <Share2 className="w-4 h-4 inline" /> Share in Safari</span>
              </li>
              <li className="pwa-ios-step">
                <span className="pwa-step-number">2.</span>
                <span>Tap "Add to Home Screen"</span>
              </li>
              <li className="pwa-ios-step">
                <span className="pwa-step-number">3.</span>
                <span>Tap "Add" to confirm</span>
              </li>
            </ol>
          </div>
        </div>
      </div>
    );
  }

  // Standard Install Prompt
  if (!showPrompt) {
    return null;
  }

  return (
    <div className="pwa-install-prompt">
      <div className="pwa-prompt-card">
        <div className="pwa-prompt-bg-circle"></div>
        <div className="pwa-prompt-bg-glow"></div>
        
        <button
          onClick={handleDismiss}
          className="pwa-close-btn"
          aria-label="Dismiss"
        >
          <X className="w-4 h-4" />
        </button>
        
        <div className="pwa-prompt-header">
          <div className="pwa-icon-container">
            {installStatus.isAndroid ? (
              <Smartphone />
            ) : (
              <Monitor />
            )}
          </div>
          <div className="pwa-prompt-text">
            <h3 className="pwa-prompt-title">Install Nebula Shield</h3>
            <p className="pwa-prompt-description">
              Get quick access and a better experience. Works offline!
            </p>
          </div>
        </div>

        <div className="pwa-actions">
          <button
            onClick={handleInstall}
            className="pwa-install-btn"
          >
            <Download className="w-5 h-5" />
            <span>Install</span>
          </button>
          <button
            onClick={handleDismiss}
            className="pwa-dismiss-btn"
          >
            Not now
          </button>
        </div>

        <div className="pwa-features">
          <span>Free</span>
          <span className="pwa-feature-dot"></span>
          <span>No app store</span>
          <span className="pwa-feature-dot"></span>
          <span>Instant access</span>
        </div>
      </div>
    </div>
  );
};

export default PWAInstallPrompt;
