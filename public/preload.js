// Secure Preload script for Electron
// Exposes minimal, validated API surface to renderer process

const { contextBridge, ipcRenderer } = require('electron');

// Input validation helpers
function isValidUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function sanitizeString(str, maxLength = 1000) {
  if (typeof str !== 'string') return '';
  return str.slice(0, maxLength);
}

// Expose minimal, validated API to renderer
contextBridge.exposeInMainWorld('electronAPI', {
  // File system dialogs (returns arrays of paths)
  selectDirectory: () => ipcRenderer.invoke('select-directory'),
  selectFile: () => ipcRenderer.invoke('select-file'),
  
  // Notifications (validate inputs)
  showNotification: (options) => {
    if (!options || typeof options !== 'object') return Promise.reject('Invalid notification options');
    const sanitized = {
      title: sanitizeString(options.title, 100),
      body: sanitizeString(options.body, 500)
    };
    return ipcRenderer.invoke('show-notification', sanitized);
  },
  
  // App info (read-only)
  getAppPath: () => ipcRenderer.invoke('get-app-path'),
  
  // External links (validate URL)
  openExternal: (url) => {
    if (!isValidUrl(url)) return Promise.reject('Invalid URL');
    return ipcRenderer.invoke('open-external', url);
  },
  
  // Platform info (read-only)
  platform: process.platform,
  isElectron: true
});
