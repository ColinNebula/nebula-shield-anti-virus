// API integration examples for React frontend
// Add this to your React project to communicate with the C++ backend

// src/services/antivirusApi.js

const API_BASE_URL = 'http://localhost:8080/api';

class AntivirusAPI {
  
  // Scan a single file
  static async scanFile(filePath) {
    try {
      const response = await fetch(`${API_BASE_URL}/scan/file`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          file_path: filePath
        }),
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error scanning file:', error);
      throw error;
    }
  }

  // Scan a directory
  static async scanDirectory(directoryPath, recursive = true) {
    try {
      const response = await fetch(`${API_BASE_URL}/scan/directory`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          directory_path: directoryPath,
          recursive: recursive
        }),
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error scanning directory:', error);
      throw error;
    }
  }

  // Get system status
  static async getSystemStatus() {
    try {
      const response = await fetch(`${API_BASE_URL}/status`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error getting system status:', error);
      throw error;
    }
  }

  // Get scan results
  static async getScanResults() {
    try {
      const response = await fetch(`${API_BASE_URL}/scan/results`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error getting scan results:', error);
      throw error;
    }
  }

  // Start real-time protection
  static async startRealTimeProtection() {
    try {
      const response = await fetch(`${API_BASE_URL}/protection/start`, {
        method: 'POST',
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error starting real-time protection:', error);
      throw error;
    }
  }

  // Stop real-time protection
  static async stopRealTimeProtection() {
    try {
      const response = await fetch(`${API_BASE_URL}/protection/stop`, {
        method: 'POST',
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error stopping real-time protection:', error);
      throw error;
    }
  }

  // Get quarantined files
  static async getQuarantinedFiles() {
    try {
      const response = await fetch(`${API_BASE_URL}/quarantine`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error getting quarantined files:', error);
      throw error;
    }
  }

  // Restore file from quarantine
  static async restoreFromQuarantine(filePath) {
    try {
      const response = await fetch(`${API_BASE_URL}/quarantine/restore`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          file_path: filePath
        }),
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error restoring file from quarantine:', error);
      throw error;
    }
  }

  // Update signatures
  static async updateSignatures() {
    try {
      const response = await fetch(`${API_BASE_URL}/signatures/update`, {
        method: 'POST',
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error updating signatures:', error);
      throw error;
    }
  }

  // Get configuration
  static async getConfiguration() {
    try {
      const response = await fetch(`${API_BASE_URL}/config`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error getting configuration:', error);
      throw error;
    }
  }

  // Update configuration
  static async updateConfiguration(config) {
    try {
      const response = await fetch(`${API_BASE_URL}/config`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(config),
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error updating configuration:', error);
      throw error;
    }
  }
}

export default AntivirusAPI;

/* 
// Example React component using the API
// Save this as a separate file: src/components/ScannerComponent.jsx

import React, { useState, useEffect } from 'react';
import AntivirusAPI from '../services/antivirusApi';

const ScannerComponent = () => {
  const [systemStatus, setSystemStatus] = useState(null);
  const [scanResults, setScanResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [filePath, setFilePath] = useState('');

  useEffect(() => {
    loadSystemStatus();
    loadScanResults();
  }, []);

  const loadSystemStatus = async () => {
    try {
      const status = await AntivirusAPI.getSystemStatus();
      setSystemStatus(status);
    } catch (error) {
      console.error('Failed to load system status:', error);
    }
  };

  const loadScanResults = async () => {
    try {
      const results = await AntivirusAPI.getScanResults();
      setScanResults(results.results || []);
    } catch (error) {
      console.error('Failed to load scan results:', error);
    }
  };

  const handleScanFile = async () => {
    if (!filePath.trim()) {
      alert('Please enter a file path');
      return;
    }

    setIsScanning(true);
    try {
      const result = await AntivirusAPI.scanFile(filePath);
      console.log('Scan result:', result);
      await loadScanResults(); // Refresh results
      alert(`Scan completed: ${result.threat_type === 'CLEAN' ? 'Clean' : 'Threat detected!'}`);
    } catch (error) {
      console.error('Scan failed:', error);
      alert('Scan failed: ' + error.message);
    } finally {
      setIsScanning(false);
    }
  };

  const handleStartProtection = async () => {
    try {
      await AntivirusAPI.startRealTimeProtection();
      await loadSystemStatus(); // Refresh status
      alert('Real-time protection started');
    } catch (error) {
      console.error('Failed to start protection:', error);
      alert('Failed to start protection: ' + error.message);
    }
  };

  const handleStopProtection = async () => {
    try {
      await AntivirusAPI.stopRealTimeProtection();
      await loadSystemStatus(); // Refresh status
      alert('Real-time protection stopped');
    } catch (error) {
      console.error('Failed to stop protection:', error);
      alert('Failed to stop protection: ' + error.message);
    }
  };

  return (
    <div className="scanner-component">
      <h2>Nebula Shield Scanner</h2>
      
      <div className="system-status">
        <h3>System Status</h3>
        {systemStatus ? (
          <div>
            <p>Server Running: {systemStatus.server_running ? 'Yes' : 'No'}</p>
            <p>Scanner Initialized: {systemStatus.scanner_initialized ? 'Yes' : 'No'}</p>
            <p>Total Scanned Files: {systemStatus.total_scanned_files}</p>
            <p>Total Threats Found: {systemStatus.total_threats_found}</p>
            <p>Real-time Protection: {systemStatus.real_time_protection ? 'Active' : 'Inactive'}</p>
          </div>
        ) : (
          <p>Loading...</p>
        )}
      </div>

      <div className="file-scanner">
        <h3>File Scanner</h3>
        <div>
          <input
            type="text"
            placeholder="Enter file path to scan"
            value={filePath}
            onChange={(e) => setFilePath(e.target.value)}
            disabled={isScanning}
          />
          <button onClick={handleScanFile} disabled={isScanning}>
            {isScanning ? 'Scanning...' : 'Scan File'}
          </button>
        </div>
      </div>

      <div className="protection-controls">
        <h3>Real-time Protection</h3>
        <button onClick={handleStartProtection}>Start Protection</button>
        <button onClick={handleStopProtection}>Stop Protection</button>
      </div>

      <div className="scan-results">
        <h3>Recent Scan Results</h3>
        {scanResults.length > 0 ? (
          <table>
            <thead>
              <tr>
                <th>File Path</th>
                <th>Threat Type</th>
                <th>Threat Name</th>
                <th>Confidence</th>
                <th>Scan Time</th>
              </tr>
            </thead>
            <tbody>
              {scanResults.slice(0, 10).map((result, index) => (
                <tr key={index}>
                  <td>{result.file_path}</td>
                  <td>{result.threat_type}</td>
                  <td>{result.threat_name || 'N/A'}</td>
                  <td>{(result.confidence * 100).toFixed(1)}%</td>
                  <td>{result.scan_time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No scan results available</p>
        )}
      </div>
    </div>
  );
};

export default ScannerComponent;
*/