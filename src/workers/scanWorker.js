/**
 * Scan Worker - REAL SCANNER
 * 
 * Runs virus scanning operations using the backend real-scanner-api.js
 * Connects to actual file scanner instead of simulation
 * 
 * Benefits:
 * - UI remains responsive during scans
 * - 60 FPS maintained
 * - Can scan thousands of files without UI lag
 * - Progress updates sent back to main thread
 * - REAL virus detection using backend scanner
 */

// Backend scanner API configuration
const SCANNER_API_URL = 'http://localhost:8081/api';

let isScanning = false;
let scanCancelled = false;

// Listen for messages from main thread
self.addEventListener('message', async (event) => {
  const { type, payload } = event.data;

  try {
    switch (type) {
      case 'SCAN_FILE':
        await handleFileScan(payload);
        break;

      case 'SCAN_DIRECTORY':
        await handleDirectoryScan(payload);
        break;

      case 'CANCEL_SCAN':
        handleCancelScan();
        break;

      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  } catch (error) {
    self.postMessage({ 
      type: 'SCAN_ERROR', 
      payload: { 
        error: error.message,
        stack: error.stack
      } 
    });
  }
});

/**
 * Handle single file scan - REAL IMPLEMENTATION
 */
async function handleFileScan(payload) {
  const { filePath } = payload;
  
  if (!filePath) {
    throw new Error('File path is required');
  }

  isScanning = true;
  scanCancelled = false;

  try {
    // Send progress update
    self.postMessage({
      type: 'SCAN_PROGRESS',
      payload: {
        progress: 25,
        currentFile: filePath
      }
    });

    if (scanCancelled) {
      throw new Error('Scan cancelled by user');
    }

    // REAL SCAN: Call backend scanner API
    const response = await fetch(`${SCANNER_API_URL}/scan/file`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ file_path: filePath })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Scan failed');
    }

    // Send progress update
    self.postMessage({
      type: 'SCAN_PROGRESS',
      payload: {
        progress: 75,
        currentFile: filePath
      }
    });

    // Get REAL scan result from backend
    const result = await response.json();
    
    // Format result for frontend
    const formattedResult = {
      file_path: result.file_path,
      file_name: filePath.split(/[\\/]/).pop(),
      threat_type: result.threat_type || 'CLEAN',
      threat_name: result.threat_name,
      severity: getSeverityFromThreatType(result.threat_type),
      file_hash: result.file_hash,
      file_size: result.file_size,
      scan_duration_ms: result.scan_duration_ms,
      scanner_engine: result.scanner_engine,
      confidence: result.confidence
    };

    // Send final result
    self.postMessage({
      type: 'SCAN_RESULT',
      payload: formattedResult
    });

  } catch (error) {
    // If backend is unavailable, show helpful error
    if (error.message.includes('fetch')) {
      throw new Error('Scanner backend not running. Start with: cd backend && npm run start:scanner');
    }
    throw error;
  } finally {
    isScanning = false;
  }
}

/**
 * Handle directory scan - REAL IMPLEMENTATION
 */
async function handleDirectoryScan(payload) {
  const { dirPath, recursive = true } = payload;
  
  if (!dirPath) {
    throw new Error('Directory path is required');
  }

  isScanning = true;
  scanCancelled = false;

  try {
    if (scanCancelled) {
      throw new Error('Scan cancelled by user');
    }

    // Send initial progress
    self.postMessage({
      type: 'SCAN_PROGRESS',
      payload: {
        progress: 10,
        currentFile: dirPath,
        scannedFiles: 0,
        totalFiles: 0
      }
    });

    // REAL SCAN: Call backend scanner API for directory
    const response = await fetch(`${SCANNER_API_URL}/scan/directory`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ 
        directory_path: dirPath,
        recursive: recursive
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Directory scan failed');
    }

    // Get REAL scan results from backend
    const data = await response.json();
    
    // Format results for frontend
    const results = data.results.map(result => ({
      file_path: result.file_path,
      file_name: result.file_path.split(/[\\/]/).pop(),
      threat_type: result.threat_type || 'CLEAN',
      threat_name: result.threat_name,
      severity: getSeverityFromThreatType(result.threat_type),
      file_hash: result.file_hash,
      file_size: result.file_size || 0,
      scan_duration_ms: result.scan_duration_ms,
      confidence: result.confidence
    }));

    // Send final results
    self.postMessage({
      type: 'SCAN_RESULT',
      payload: {
        results,
        summary: {
          totalFiles: data.total_files,
          scannedFiles: data.total_files,
          threatsFound: data.threats_found,
          cleanFiles: data.total_files - data.threats_found,
          scanDuration: data.scan_duration_ms,
          scannerEngine: data.scanner_engine
        }
      }
    });

  } catch (error) {
    // If backend is unavailable, show helpful error
    if (error.message.includes('fetch')) {
      throw new Error('Scanner backend not running. Start with: cd backend && npm run start:scanner');
    }
    throw error;
  } finally {
    isScanning = false;
  }
}

/**
 * Cancel ongoing scan
 */
function handleCancelScan() {
  scanCancelled = true;
  isScanning = false;
  
  self.postMessage({
    type: 'SCAN_CANCELLED',
    payload: { message: 'Scan cancelled by user' }
  });
}

/**
 * Helper: Map threat type to severity
 */
function getSeverityFromThreatType(threatType) {
  const severityMap = {
    'CLEAN': 'clean',
    'SUSPICIOUS': 'medium',
    'MALWARE': 'high',
    'VIRUS': 'high',
    'TROJAN': 'critical',
    'RANSOMWARE': 'critical',
    'ROOTKIT': 'critical',
    'ADWARE': 'low',
    'SPYWARE': 'high'
  };
  return severityMap[threatType] || 'medium';
}

// Worker initialization
console.log('✓ Scan Worker initialized and ready');

self.postMessage({
  type: 'WORKER_READY',
  payload: { message: 'Scan worker initialized successfully' }
});
