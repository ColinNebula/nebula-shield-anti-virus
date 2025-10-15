import { useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';

/**
 * Custom hook for keyboard shortcuts
 * @param {boolean} enabled - Whether shortcuts are enabled
 */
const useKeyboardShortcuts = (enabled = true) => {
  const navigate = useNavigate();

  const handleKeyPress = useCallback((event) => {
    if (!enabled) return;

    // Ignore if user is typing in an input/textarea
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(event.target.tagName)) {
      return;
    }

    const { key, ctrlKey, altKey, shiftKey } = event;

    // Ctrl + K: Quick search (focus search)
    if (ctrlKey && key === 'k') {
      event.preventDefault();
      const searchInput = document.querySelector('input[type="search"], input[placeholder*="Search"]');
      if (searchInput) {
        searchInput.focus();
        toast('🔍 Search activated', { duration: 1000 });
      }
    }

    // Alt + D: Dashboard
    if (altKey && key === 'd') {
      event.preventDefault();
      navigate('/dashboard');
      toast('🏠 Dashboard', { duration: 1000 });
    }

    // Alt + S: Scanner
    if (altKey && key === 's') {
      event.preventDefault();
      navigate('/scanner');
      toast('🔍 Scanner', { duration: 1000 });
    }

    // Alt + Q: Quarantine
    if (altKey && key === 'q') {
      event.preventDefault();
      navigate('/quarantine');
      toast('🔒 Quarantine', { duration: 1000 });
    }

    // Alt + N: Network Protection
    if (altKey && key === 'n') {
      event.preventDefault();
      navigate('/network-protection');
      toast('🌐 Network Protection', { duration: 1000 });
    }

    // Alt + M: ML Detection
    if (altKey && key === 'm') {
      event.preventDefault();
      navigate('/ml-detection');
      toast('🧠 ML Detection', { duration: 1000 });
    }

    // Alt + P: Settings
    if (altKey && key === 'p') {
      event.preventDefault();
      navigate('/settings');
      toast('⚙️ Settings', { duration: 1000 });
    }

    // Shift + ? : Show shortcuts help
    if (shiftKey && key === '?') {
      event.preventDefault();
      showShortcutsHelp();
    }

    // Esc: Close modals/overlays
    if (key === 'Escape') {
      const modal = document.querySelector('[role="dialog"], .modal');
      if (modal) {
        const closeButton = modal.querySelector('[aria-label*="close"], .close-button, .modal-close');
        if (closeButton) {
          closeButton.click();
        }
      }
    }
  }, [enabled, navigate]);

  const showShortcutsHelp = () => {
    const shortcuts = [
      { keys: 'Ctrl + K', action: 'Quick search' },
      { keys: 'Alt + D', action: 'Go to Dashboard' },
      { keys: 'Alt + S', action: 'Go to Scanner' },
      { keys: 'Alt + Q', action: 'Go to Quarantine' },
      { keys: 'Alt + N', action: 'Network Protection' },
      { keys: 'Alt + M', action: 'ML Detection' },
      { keys: 'Alt + P', action: 'Settings' },
      { keys: 'Esc', action: 'Close modals' },
      { keys: 'Shift + ?', action: 'Show this help' }
    ];

    const helpHTML = `
      <div style="text-align: left;">
        <h3 style="margin: 0 0 1rem 0; color: #f1f5f9;">⌨️ Keyboard Shortcuts</h3>
        ${shortcuts.map(s => `
          <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
            <code style="background: rgba(79, 70, 229, 0.2); padding: 0.25rem 0.5rem; border-radius: 4px; color: #a78bfa;">${s.keys}</code>
            <span style="color: #cbd5e1; margin-left: 1rem;">${s.action}</span>
          </div>
        `).join('')}
      </div>
    `;

    // Create custom toast with HTML
    const toastId = toast(
      <div dangerouslySetInnerHTML={{ __html: helpHTML }} />,
      {
        duration: 8000,
        style: {
          minWidth: '400px',
          background: 'var(--card-bg)',
          border: '1px solid var(--border-primary)',
        }
      }
    );
  };

  useEffect(() => {
    window.addEventListener('keydown', handleKeyPress);

    return () => {
      window.removeEventListener('keydown', handleKeyPress);
    };
  }, [handleKeyPress]);

  return { showShortcutsHelp };
};

export default useKeyboardShortcuts;
