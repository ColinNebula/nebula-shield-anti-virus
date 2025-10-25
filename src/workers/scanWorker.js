/**
 * Scan Worker
 * 
 * Runs virus scanning operations in a Web Worker to keep the UI responsive.
 * This prevents the main thread from blocking during intensive scanning operations.
 * 
 * Benefits:
 * - UI remains responsive during scans
 * - 60 FPS maintained
 * - Can scan thousands of files without UI lag
 * - Progress updates sent back to main thread
 */

// Note: In a Web Worker, we don't have access to DOM or most browser APIs
// We need to import the scanner service and communicate via messages

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
 * Handle single file scan
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

    // Simulate scanning (in production, this would use the actual scanner)
    // Note: File system access in workers requires special handling
    // You may need to pass file content from main thread
    await simulateScan(filePath, 1000);

    if (scanCancelled) {
      throw new Error('Scan cancelled by user');
    }

    // Send progress update
    self.postMessage({
      type: 'SCAN_PROGRESS',
      payload: {
        progress: 75,
        currentFile: filePath
      }
    });

    // Simulate result
    const result = {
      file_path: filePath,
      file_name: filePath.split(/[\\/]/).pop(),
      threat_type: Math.random() > 0.7 ? 'TROJAN' : 'CLEAN',
      threat_name: Math.random() > 0.7 ? 'Trojan.Generic.Test' : null,
      severity: Math.random() > 0.7 ? 'high' : 'clean',
      file_hash: generateHash(filePath),
      file_size: Math.floor(Math.random() * 10000000)
    };

    // Send final result
    self.postMessage({
      type: 'SCAN_RESULT',
      payload: result
    });

  } catch (error) {
    throw error;
  } finally {
    isScanning = false;
  }
}

/**
 * Handle directory scan
 */
async function handleDirectoryScan(payload) {
  const { dirPath, recursive } = payload;
  
  if (!dirPath) {
    throw new Error('Directory path is required');
  }

  isScanning = true;
  scanCancelled = false;

  try {
    // Simulate directory traversal
    const totalFiles = Math.floor(Math.random() * 50) + 10;
    const results = [];

    for (let i = 0; i < totalFiles; i++) {
      if (scanCancelled) {
        throw new Error('Scan cancelled by user');
      }

      const fileName = `file_${i + 1}.${['exe', 'dll', 'txt', 'doc'][Math.floor(Math.random() * 4)]}`;
      const filePath = `${dirPath}\\${fileName}`;
      
      // Send progress update
      const progress = Math.floor((i / totalFiles) * 100);
      self.postMessage({
        type: 'SCAN_PROGRESS',
        payload: {
          progress,
          currentFile: filePath,
          scannedFiles: i,
          totalFiles
        }
      });

      // Simulate scanning each file
      await simulateScan(filePath, 50);

      const isThreat = Math.random() > 0.8;
      const result = {
        file_path: filePath,
        file_name: fileName,
        threat_type: isThreat ? ['TROJAN', 'MALWARE', 'ADWARE'][Math.floor(Math.random() * 3)] : 'CLEAN',
        threat_name: isThreat ? 'Threat.Generic.Test' : null,
        severity: isThreat ? ['critical', 'high', 'medium'][Math.floor(Math.random() * 3)] : 'clean',
        file_hash: generateHash(filePath),
        file_size: Math.floor(Math.random() * 10000000)
      };

      results.push(result);
    }

    // Send final results
    self.postMessage({
      type: 'SCAN_RESULT',
      payload: {
        results,
        summary: {
          totalFiles,
          scannedFiles: totalFiles,
          threatsFound: results.filter(r => r.threat_type !== 'CLEAN').length,
          cleanFiles: results.filter(r => r.threat_type === 'CLEAN').length
        }
      }
    });

  } catch (error) {
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
 * Simulate scanning delay
 */
function simulateScan(filePath, delay) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve();
    }, delay);
  });
}

/**
 * Generate simple hash for file path
 */
function generateHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return Math.abs(hash).toString(16).padStart(16, '0');
}

// Worker initialization
console.log('✓ Scan Worker initialized and ready');

self.postMessage({
  type: 'WORKER_READY',
  payload: { message: 'Scan worker initialized successfully' }
});
