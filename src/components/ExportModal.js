import React, { useState } from 'react';
import { Download, X, FileJson, FileSpreadsheet, FileText, Calendar, Filter, Info } from 'lucide-react';
import toast from 'react-hot-toast';
import './ExportModal.css';

const ExportModal = ({ isOpen, onClose, onExport, totalLogs, filters }) => {
  const [exportFormat, setExportFormat] = useState('json');
  const [exportOptions, setExportOptions] = useState({
    includeForensics: true,
    includeStats: true,
    maxLogs: 1000,
    dateRange: 'all'
  });

  if (!isOpen) return null;

  const handleExport = async () => {
    try {
      toast.loading('Preparing export...', { id: 'export' });
      
      const options = {
        ...exportOptions,
        dateRange: getDateRangeLabel()
      };
      
      await onExport(exportFormat, filters, options);
      
      toast.success(`Successfully exported ${totalLogs} logs as ${exportFormat.toUpperCase()}!`, { 
        id: 'export',
        duration: 3000,
        icon: '✅'
      });
      
      onClose();
    } catch (error) {
      toast.error(`Export failed: ${error.message}`, { 
        id: 'export',
        duration: 4000
      });
    }
  };

  const getDateRangeLabel = () => {
    const ranges = {
      'all': 'All Time',
      'today': 'Today',
      'week': 'Last 7 Days',
      'month': 'Last 30 Days'
    };
    return ranges[exportOptions.dateRange] || 'All Time';
  };

  const getFormatIcon = (format) => {
    switch(format) {
      case 'json': return <FileJson size={20} />;
      case 'csv': return <FileSpreadsheet size={20} />;
      case 'pdf': return <FileText size={20} />;
      default: return <Download size={20} />;
    }
  };

  const getFormatDescription = (format) => {
    switch(format) {
      case 'json':
        return 'Machine-readable format with complete data structure. Ideal for backup and data processing.';
      case 'csv':
        return 'Spreadsheet-compatible format. Perfect for Excel, Google Sheets, or data analysis tools.';
      case 'pdf':
        return 'Professional report with charts and statistics. Best for presentations and documentation.';
      default:
        return '';
    }
  };

  const estimatedFileSize = () => {
    const avgSizePerLog = {
      json: 1.5, // KB
      csv: 0.5,
      pdf: 0.3
    };
    const size = (totalLogs * (avgSizePerLog[exportFormat] || 1)) / 1024;
    return size > 1 ? `~${size.toFixed(1)} MB` : `~${(size * 1024).toFixed(0)} KB`;
  };

  return (
    <div className="export-modal-overlay" onClick={onClose}>
      <div className="export-modal" onClick={(e) => e.stopPropagation()}>
        <div className="export-modal-header">
          <div>
            <h2><Download size={24} /> Export Firewall Logs</h2>
            <p>Export {totalLogs.toLocaleString()} threat events</p>
          </div>
          <button className="close-button" onClick={onClose}>
            <X size={24} />
          </button>
        </div>

        <div className="export-modal-body">
          {/* Format Selection */}
          <div className="export-section">
            <h3>Select Export Format</h3>
            <div className="format-options">
              {['json', 'csv', 'pdf'].map(format => (
                <button
                  key={format}
                  className={`format-option ${exportFormat === format ? 'active' : ''}`}
                  onClick={() => setExportFormat(format)}
                >
                  <div className="format-icon">
                    {getFormatIcon(format)}
                  </div>
                  <div className="format-details">
                    <span className="format-name">{format.toUpperCase()}</span>
                    <span className="format-desc">{getFormatDescription(format)}</span>
                  </div>
                  {exportFormat === format && (
                    <div className="format-check">✓</div>
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Export Options */}
          <div className="export-section">
            <h3><Filter size={18} /> Export Options</h3>
            
            <div className="export-options">
              {/* Include Forensics (CSV only) */}
              {exportFormat === 'csv' && (
                <label className="option-checkbox">
                  <input
                    type="checkbox"
                    checked={exportOptions.includeForensics}
                    onChange={(e) => setExportOptions({
                      ...exportOptions,
                      includeForensics: e.target.checked
                    })}
                  />
                  <span>
                    <strong>Include Forensic Data</strong>
                    <small>Add geolocation, user agent, and packet details</small>
                  </span>
                </label>
              )}

              {/* Include Statistics */}
              {exportFormat !== 'csv' && (
                <label className="option-checkbox">
                  <input
                    type="checkbox"
                    checked={exportOptions.includeStats}
                    onChange={(e) => setExportOptions({
                      ...exportOptions,
                      includeStats: e.target.checked
                    })}
                  />
                  <span>
                    <strong>Include Statistics</strong>
                    <small>Add summary statistics and threat breakdown</small>
                  </span>
                </label>
              )}

              {/* Max Logs (PDF only) */}
              {exportFormat === 'pdf' && (
                <div className="option-field">
                  <label>
                    <strong>Maximum Logs in Report</strong>
                    <small>PDF reports are limited to prevent large file sizes</small>
                  </label>
                  <select
                    value={exportOptions.maxLogs}
                    onChange={(e) => setExportOptions({
                      ...exportOptions,
                      maxLogs: parseInt(e.target.value)
                    })}
                  >
                    <option value={25}>25 logs</option>
                    <option value={50}>50 logs</option>
                    <option value={100}>100 logs</option>
                    <option value={250}>250 logs</option>
                  </select>
                </div>
              )}

              {/* Date Range Filter */}
              <div className="option-field">
                <label>
                  <Calendar size={16} />
                  <strong>Date Range</strong>
                </label>
                <select
                  value={exportOptions.dateRange}
                  onChange={(e) => setExportOptions({
                    ...exportOptions,
                    dateRange: e.target.value
                  })}
                >
                  <option value="all">All Time</option>
                  <option value="today">Today</option>
                  <option value="week">Last 7 Days</option>
                  <option value="month">Last 30 Days</option>
                </select>
              </div>
            </div>
          </div>

          {/* Active Filters Display */}
          {(filters.severity !== 'all' || filters.threatType !== 'all' || filters.blocked !== 'all') && (
            <div className="export-section">
              <h3><Info size={18} /> Active Filters</h3>
              <div className="active-filters">
                {filters.severity !== 'all' && (
                  <span className="filter-tag">Severity: {filters.severity}</span>
                )}
                {filters.threatType !== 'all' && (
                  <span className="filter-tag">Type: {filters.threatType}</span>
                )}
                {filters.blocked !== 'all' && (
                  <span className="filter-tag">Status: {filters.blocked}</span>
                )}
              </div>
              <p className="filters-note">These filters will be applied to the export</p>
            </div>
          )}

          {/* Export Summary */}
          <div className="export-summary">
            <div className="summary-item">
              <span className="summary-label">Format:</span>
              <span className="summary-value">{exportFormat.toUpperCase()}</span>
            </div>
            <div className="summary-item">
              <span className="summary-label">Logs:</span>
              <span className="summary-value">{totalLogs.toLocaleString()}</span>
            </div>
            <div className="summary-item">
              <span className="summary-label">Estimated Size:</span>
              <span className="summary-value">{estimatedFileSize()}</span>
            </div>
            <div className="summary-item">
              <span className="summary-label">Date Range:</span>
              <span className="summary-value">{getDateRangeLabel()}</span>
            </div>
          </div>
        </div>

        <div className="export-modal-footer">
          <button className="btn-cancel" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-export-confirm" onClick={handleExport}>
            <Download size={18} />
            Export {exportFormat.toUpperCase()}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ExportModal;
