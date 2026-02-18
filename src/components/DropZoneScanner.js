import React, { useState, useCallback, useRef } from 'react';
import { Upload, FileCheck, AlertTriangle, FolderOpen, X } from 'lucide-react';
import toast from 'react-hot-toast';
import './DropZoneScanner.css';

const DropZoneScanner = ({ onScan, className = '' }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [files, setFiles] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);
  const dragCounter = useRef(0);

  const handleDragEnter = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current++;
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setIsDragging(true);
    }
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current--;
    if (dragCounter.current === 0) {
      setIsDragging(false);
    }
  }, []);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    dragCounter.current = 0;

    const droppedFiles = Array.from(e.dataTransfer.files);
    if (droppedFiles.length > 0) {
      handleFiles(droppedFiles);
    }
  }, []);

  const handleFiles = useCallback((fileList) => {
    const newFiles = Array.from(fileList).map((file) => ({
      file,
      name: file.name,
      size: file.size,
      type: file.type || 'unknown',
      path: file.path || file.webkitRelativePath || file.name,
      status: 'pending',
      threat: null
    }));

    setFiles(newFiles);
    toast.success(`${newFiles.length} file(s) ready to scan`);
  }, []);

  const handleFileSelect = useCallback((e) => {
    const selectedFiles = e.target.files;
    if (selectedFiles && selectedFiles.length > 0) {
      handleFiles(selectedFiles);
    }
  }, [handleFiles]);

  const startScan = useCallback(async () => {
    if (files.length === 0) {
      toast.error('No files to scan');
      return;
    }

    setIsScanning(true);
    const scanResults = [];

    try {
      // Show notification
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('Nebula Shield - Scan Started', {
          body: `Scanning ${files.length} file(s)...`,
          icon: '/logo192.png'
        });
      }

      for (let i = 0; i < files.length; i++) {
        const fileItem = files[i];
        
        // Update status
        setFiles((prev) => 
          prev.map((f, idx) => 
            idx === i ? { ...f, status: 'scanning' } : f
          )
        );

        // Perform scan
        const result = await onScan(fileItem.file, fileItem.path);
        
        // Update with result
        setFiles((prev) => 
          prev.map((f, idx) => 
            idx === i ? { 
              ...f, 
              status: result.threat ? 'threat' : 'clean',
              threat: result.threat 
            } : f
          )
        );

        scanResults.push(result);
      }

      // Show completion notification
      const threats = scanResults.filter(r => r.threat);
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('Nebula Shield - Scan Complete', {
          body: threats.length > 0 
            ? `Found ${threats.length} threat(s)!`
            : 'All files are clean',
          icon: '/logo192.png'
        });
      }

      if (threats.length > 0) {
        toast.error(`Found ${threats.length} threat(s)!`, { duration: 5000 });
      } else {
        toast.success('All files are clean!');
      }

    } catch (error) {
      console.error('Scan error:', error);
      toast.error('Scan failed: ' + error.message);
    } finally {
      setIsScanning(false);
    }
  }, [files, onScan]);

  const clearFiles = useCallback(() => {
    setFiles([]);
    if (fileInputRef.current) fileInputRef.current.value = '';
    if (folderInputRef.current) folderInputRef.current.value = '';
  }, []);

  const removeFile = useCallback((index) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  }, []);

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'clean':
        return <FileCheck className="status-icon clean" />;
      case 'threat':
        return <AlertTriangle className="status-icon threat" />;
      case 'scanning':
        return <div className="spinner-small"></div>;
      default:
        return <Upload className="status-icon pending" />;
    }
  };

  return (
    <div className={`dropzone-scanner ${className}`}>
      <div
        className={`dropzone ${isDragging ? 'dragging' : ''}`}
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
      >
        <div className="dropzone-content">
          <Upload className="dropzone-icon" size={48} />
          <h3>Drag & Drop Files to Scan</h3>
          <p>or click to browse</p>
          
          <div className="dropzone-buttons">
            <button
              className="btn-select-files"
              onClick={() => fileInputRef.current?.click()}
              disabled={isScanning}
            >
              <Upload size={18} />
              Select Files
            </button>
            <button
              className="btn-select-folder"
              onClick={() => folderInputRef.current?.click()}
              disabled={isScanning}
            >
              <FolderOpen size={18} />
              Select Folder
            </button>
          </div>

          <input
            ref={fileInputRef}
            type="file"
            multiple
            onChange={handleFileSelect}
            style={{ display: 'none' }}
            accept="*/*"
          />
          <input
            ref={folderInputRef}
            type="file"
            webkitdirectory=""
            directory=""
            multiple
            onChange={handleFileSelect}
            style={{ display: 'none' }}
          />
        </div>
      </div>

      {files.length > 0 && (
        <div className="files-list">
          <div className="files-header">
            <h4>{files.length} File(s) Ready</h4>
            <div className="files-actions">
              {!isScanning && (
                <>
                  <button className="btn-scan-primary" onClick={startScan}>
                    <FileCheck size={18} />
                    Scan All
                  </button>
                  <button className="btn-clear" onClick={clearFiles}>
                    <X size={18} />
                    Clear
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="files-container">
            {files.map((fileItem, index) => (
              <div key={index} className={`file-item ${fileItem.status}`}>
                <div className="file-info">
                  {getStatusIcon(fileItem.status)}
                  <div className="file-details">
                    <div className="file-name">{fileItem.name}</div>
                    <div className="file-meta">
                      {formatFileSize(fileItem.size)} • {fileItem.type}
                    </div>
                    {fileItem.threat && (
                      <div className="file-threat">
                        Threat: {fileItem.threat}
                      </div>
                    )}
                  </div>
                </div>
                {!isScanning && fileItem.status === 'pending' && (
                  <button
                    className="btn-remove"
                    onClick={() => removeFile(index)}
                    title="Remove"
                  >
                    <X size={16} />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default DropZoneScanner;
