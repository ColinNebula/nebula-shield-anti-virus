// Example: Integrating DropZoneScanner into Scanner.js

import React, { useState } from 'react';
import DropZoneScanner from './DropZoneScanner';
import antivirusApi from '../services/antivirusApi';
import toast from 'react-hot-toast';

function ScannerWithDropZone() {
  const [scanResults, setScanResults] = useState([]);

  const handleFileScan = async (file, filePath) => {
    try {
      // Call your actual scan API
      const result = await antivirusApi.scanFile(file);
      
      // Return the result in the expected format
      return {
        threat: result.isThreat ? result.threatName : null,
        scanTime: result.scanTime,
        fileSize: file.size
      };
    } catch (error) {
      console.error('Scan error:', error);
      toast.error(`Failed to scan ${file.name}`);
      return { threat: null, error: error.message };
    }
  };

  return (
    <div className="scanner-page">
      <h1>File Scanner</h1>
      
      {/* Traditional scan buttons */}
      <div className="scan-buttons">
        <button className="btn-primary">Quick Scan</button>
        <button className="btn-secondary">Full Scan</button>
      </div>

      {/* New Drag & Drop Scanner */}
      <div className="drop-zone-section">
        <h2>Drag & Drop Files to Scan</h2>
        <DropZoneScanner onScan={handleFileScan} />
      </div>

      {/* Scan Results */}
      {scanResults.length > 0 && (
        <div className="scan-results">
          <h3>Recent Scans</h3>
          {/* Display results */}
        </div>
      )}
    </div>
  );
}

export default ScannerWithDropZone;
