import { useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../contexts/ThemeContext';
import toast from 'react-hot-toast';

/**
 * Custom hook for keyboard shortcuts
 * @param {boolean} enabled - Whether shortcuts are enabled
 * @param {Function} onShowShortcuts - Callback to show shortcuts modal
 */
const useKeyboardShortcuts = (enabled = true, onShowShortcuts) => {
  const navigate = useNavigate();
  const themeContext = useTheme();
  const toggleTheme = themeContext?.toggleTheme || (() => {});

  const handleKeyPress = useCallback((event) => {
    if (!enabled) return;

    // Ignore if user is typing in an input/textarea
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(event.target.tagName)) {
      // Allow Esc to close/blur input fields
      if (event.key === 'Escape') {
        event.target.blur();
      }
      return;
    }

    const { key, ctrlKey, altKey, shiftKey, metaKey } = event;
    const isMac = /Mac|iPod|iPhone|iPad/.test(navigator.platform);
    const cmdOrCtrl = isMac ? metaKey : ctrlKey;

    // Ctrl/Cmd + K: Show keyboard shortcuts
    if (cmdOrCtrl && key === 'k') {
      event.preventDefault();
      if (onShowShortcuts) {
        onShowShortcuts();
      }
    }

    // Ctrl/Cmd + D: Toggle dark mode
    if (cmdOrCtrl && key === 'd') {
      event.preventDefault();
      toggleTheme();
      toast.success('Theme toggled', { duration: 1500 });
    }

    // Ctrl/Cmd + S: Quick scan
    if (cmdOrCtrl && key === 's') {
      event.preventDefault();
      navigate('/scanner');
      toast('🔍 Quick Scan', { duration: 1000 });
    }

    // Ctrl/Cmd + F: Full system scan
    if (cmdOrCtrl && key === 'f') {
      event.preventDefault();
      navigate('/scanner');
      toast('� Full System Scan', { duration: 1000 });
    }

    // Ctrl/Cmd + Q: Quarantine
    if (cmdOrCtrl && key === 'q') {
      event.preventDefault();
      navigate('/quarantine');
      toast('🔒 Quarantine', { duration: 1000 });
    }

    // Ctrl/Cmd + H: Dashboard/Home
    if (cmdOrCtrl && key === 'h') {
      event.preventDefault();
      navigate('/dashboard');
      toast('🏠 Dashboard', { duration: 1000 });
    }

    // Ctrl/Cmd + ,: Settings
    if (cmdOrCtrl && key === ',') {
      event.preventDefault();
      navigate('/settings');
      toast('⚙️ Settings', { duration: 1000 });
    }

    // Ctrl/Cmd + 1-5: Quick navigation
    if (cmdOrCtrl && !shiftKey) {
      switch (key) {
        case '1':
          event.preventDefault();
          navigate('/dashboard');
          break;
        case '2':
          event.preventDefault();
          navigate('/scanner');
          break;
        case '3':
          event.preventDefault();
          navigate('/quarantine');
          break;
        case '4':
          event.preventDefault();
          navigate('/network-protection');
          break;
        case '5':
          event.preventDefault();
          navigate('/settings');
          break;
      }
    }

    // Alt + Arrow keys: Navigate back/forward
    if (altKey && (key === 'ArrowLeft' || key === 'ArrowRight')) {
      event.preventDefault();
      if (key === 'ArrowLeft') {
        window.history.back();
        toast('← Back', { duration: 1000 });
      } else {
        window.history.forward();
        toast('→ Forward', { duration: 1000 });
      }
    }

    // Ctrl/Cmd + R: Refresh
    if (cmdOrCtrl && key === 'r') {
      // Allow default browser refresh
      toast('🔄 Refreshing...', { duration: 1000 });
    }

    // Esc: Close modals/overlays
    if (key === 'Escape') {
      const modal = document.querySelector('[role="dialog"], .modal, .shortcuts-modal-overlay');
      if (modal) {
        const closeButton = modal.querySelector('[aria-label*="lose"], .close-button, .modal-close, .shortcuts-close');
        if (closeButton) {
          closeButton.click();
        }
      }
    }
  }, [enabled, navigate, toggleTheme, onShowShortcuts]);

  useEffect(() => {
    window.addEventListener('keydown', handleKeyPress);

    return () => {
      window.removeEventListener('keydown', handleKeyPress);
    };
  }, [handleKeyPress]);
};

export default useKeyboardShortcuts;
