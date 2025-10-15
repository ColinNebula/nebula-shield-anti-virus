import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CheckSquare,
  Square,
  Trash2,
  Archive,
  Download,
  Shield,
  AlertTriangle,
  X,
  Loader
} from 'lucide-react';
import toast from 'react-hot-toast';
import './BulkOperations.css';

const BulkOperations = ({ 
  items = [], 
  selectedItems = [], 
  onSelectionChange, 
  onBulkAction,
  actions = ['delete', 'quarantine', 'restore', 'download']
}) => {
  const [isProcessing, setIsProcessing] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [pendingAction, setPendingAction] = useState(null);

  const allSelected = items.length > 0 && selectedItems.length === items.length;
  const someSelected = selectedItems.length > 0 && selectedItems.length < items.length;

  const handleSelectAll = () => {
    if (allSelected) {
      onSelectionChange([]);
    } else {
      onSelectionChange(items.map(item => item.id));
    }
  };

  const handleBulkAction = async (action) => {
    if (selectedItems.length === 0) {
      toast.error('No items selected');
      return;
    }

    // Show confirmation for destructive actions
    if (['delete', 'quarantine'].includes(action)) {
      setPendingAction(action);
      setShowConfirm(true);
      return;
    }

    await executeBulkAction(action);
  };

  const executeBulkAction = async (action) => {
    setIsProcessing(true);
    setShowConfirm(false);

    try {
      await onBulkAction(action, selectedItems);
      
      const actionLabels = {
        delete: 'deleted',
        quarantine: 'quarantined',
        restore: 'restored',
        download: 'downloaded'
      };

      toast.success(`${selectedItems.length} item(s) ${actionLabels[action]}`);
      onSelectionChange([]);
    } catch (error) {
      toast.error(`Failed to ${action} items: ${error.message}`);
    } finally {
      setIsProcessing(false);
      setPendingAction(null);
    }
  };

  const actionConfig = {
    delete: {
      label: 'Delete',
      icon: Trash2,
      color: '#ef4444',
      confirmMessage: 'Are you sure you want to delete these items? This action cannot be undone.'
    },
    quarantine: {
      label: 'Quarantine',
      icon: Shield,
      color: '#f59e0b',
      confirmMessage: 'Quarantine selected items? They will be isolated from your system.'
    },
    restore: {
      label: 'Restore',
      icon: Archive,
      color: '#10b981'
    },
    download: {
      label: 'Download',
      icon: Download,
      color: '#3b82f6'
    }
  };

  return (
    <>
      <div className="bulk-operations">
        <div className="bulk-select">
          <button 
            className="select-all-btn"
            onClick={handleSelectAll}
            disabled={items.length === 0}
          >
            {allSelected ? (
              <CheckSquare size={20} className="checked" />
            ) : someSelected ? (
              <Square size={20} className="indeterminate" />
            ) : (
              <Square size={20} />
            )}
            <span>
              {allSelected ? 'Deselect All' : `Select All (${items.length})`}
            </span>
          </button>

          {selectedItems.length > 0 && (
            <span className="selection-count">
              {selectedItems.length} selected
            </span>
          )}
        </div>

        {selectedItems.length > 0 && (
          <motion.div
            className="bulk-actions"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
          >
            {actions.map(action => {
              const config = actionConfig[action];
              if (!config) return null;

              const Icon = config.icon;

              return (
                <button
                  key={action}
                  className={`bulk-action-btn bulk-${action}`}
                  onClick={() => handleBulkAction(action)}
                  disabled={isProcessing}
                  style={{ '--action-color': config.color }}
                >
                  {isProcessing ? (
                    <Loader size={16} className="spinning" />
                  ) : (
                    <Icon size={16} />
                  )}
                  {config.label}
                </button>
              );
            })}
          </motion.div>
        )}
      </div>

      {/* Confirmation Modal */}
      <AnimatePresence>
        {showConfirm && pendingAction && (
          <motion.div
            className="bulk-confirm-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowConfirm(false)}
          >
            <motion.div
              className="bulk-confirm-modal"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="confirm-header">
                <AlertTriangle size={32} />
                <h3>Confirm {actionConfig[pendingAction].label}</h3>
                <button 
                  className="close-btn"
                  onClick={() => setShowConfirm(false)}
                >
                  <X size={20} />
                </button>
              </div>

              <div className="confirm-body">
                <p>{actionConfig[pendingAction].confirmMessage}</p>
                <div className="confirm-details">
                  <strong>{selectedItems.length}</strong> item(s) will be affected
                </div>
              </div>

              <div className="confirm-actions">
                <button
                  className="btn-cancel"
                  onClick={() => setShowConfirm(false)}
                >
                  Cancel
                </button>
                <button
                  className="btn-confirm"
                  onClick={() => executeBulkAction(pendingAction)}
                  style={{ background: actionConfig[pendingAction].color }}
                >
                  {actionConfig[pendingAction].label}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};

export default BulkOperations;
