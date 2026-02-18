import React, { useState } from 'react';
import { X, Keyboard, Search, Zap } from 'lucide-react';
import './KeyboardShortcutsModal.css';

const KeyboardShortcutsModal = ({ isOpen, onClose }) => {
  const [searchTerm, setSearchTerm] = useState('');

  const shortcuts = [
    {
      category: 'General',
      items: [
        { keys: ['Ctrl', 'K'], description: 'Show keyboard shortcuts' },
        { keys: ['Ctrl', 'S'], description: 'Quick scan' },
        { keys: ['Ctrl', 'F'], description: 'Full system scan' },
        { keys: ['Ctrl', 'Q'], description: 'Open quarantine' },
        { keys: ['Ctrl', 'H'], description: 'Go to home/dashboard' },
        { keys: ['Ctrl', ','], description: 'Open settings' },
        { keys: ['Esc'], description: 'Close modal/dialog' }
      ]
    },
    {
      category: 'Navigation',
      items: [
        { keys: ['Ctrl', '1'], description: 'Dashboard' },
        { keys: ['Ctrl', '2'], description: 'Scanner' },
        { keys: ['Ctrl', '3'], description: 'Quarantine' },
        { keys: ['Ctrl', '4'], description: 'Protection' },
        { keys: ['Ctrl', '5'], description: 'Settings' },
        { keys: ['Alt', '←'], description: 'Go back' },
        { keys: ['Alt', '→'], description: 'Go forward' }
      ]
    },
    {
      category: 'Actions',
      items: [
        { keys: ['Ctrl', 'R'], description: 'Refresh/Reload' },
        { keys: ['Ctrl', 'D'], description: 'Toggle dark mode' },
        { keys: ['Ctrl', 'N'], description: 'New scan' },
        { keys: ['Delete'], description: 'Delete selected item' },
        { keys: ['Ctrl', 'A'], description: 'Select all' },
        { keys: ['Ctrl', 'Z'], description: 'Undo' }
      ]
    },
    {
      category: 'Protection',
      items: [
        { keys: ['Ctrl', 'P'], description: 'Toggle real-time protection' },
        { keys: ['Ctrl', 'Shift', 'F'], description: 'Toggle firewall' },
        { keys: ['Ctrl', 'Shift', 'E'], description: 'Toggle email protection' },
        { keys: ['Ctrl', 'U'], description: 'Check for updates' }
      ]
    }
  ];

  const filteredShortcuts = shortcuts.map(category => ({
    ...category,
    items: category.items.filter(item =>
      item.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.keys.some(key => key.toLowerCase().includes(searchTerm.toLowerCase()))
    )
  })).filter(category => category.items.length > 0);

  if (!isOpen) return null;

  return (
    <div className="shortcuts-modal-overlay" onClick={onClose}>
      <div className="shortcuts-modal" onClick={(e) => e.stopPropagation()}>
        <div className="shortcuts-header">
          <div className="shortcuts-title">
            <Keyboard className="shortcuts-icon" />
            <h2>Keyboard Shortcuts</h2>
          </div>
          <button className="shortcuts-close" onClick={onClose} aria-label="Close">
            <X size={20} />
          </button>
        </div>

        <div className="shortcuts-search">
          <Search className="search-icon" size={18} />
          <input
            type="text"
            placeholder="Search shortcuts..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            autoFocus
          />
        </div>

        <div className="shortcuts-content">
          {filteredShortcuts.map((category, index) => (
            <div key={index} className="shortcuts-category">
              <h3 className="category-title">
                <Zap size={16} />
                {category.category}
              </h3>
              <div className="shortcuts-list">
                {category.items.map((item, itemIndex) => (
                  <div key={itemIndex} className="shortcut-item">
                    <div className="shortcut-keys">
                      {item.keys.map((key, keyIndex) => (
                        <React.Fragment key={keyIndex}>
                          <kbd className="key">{key}</kbd>
                          {keyIndex < item.keys.length - 1 && (
                            <span className="key-separator">+</span>
                          )}
                        </React.Fragment>
                      ))}
                    </div>
                    <div className="shortcut-description">{item.description}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}

          {filteredShortcuts.length === 0 && (
            <div className="no-results">
              <Search size={48} />
              <p>No shortcuts found for "{searchTerm}"</p>
            </div>
          )}
        </div>

        <div className="shortcuts-footer">
          <p className="shortcuts-hint">
            Press <kbd className="key">Esc</kbd> to close
          </p>
        </div>
      </div>
    </div>
  );
};

export default KeyboardShortcutsModal;
