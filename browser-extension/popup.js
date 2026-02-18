/**
 * Nebula Shield Browser Extension - Popup Script
 */

// Load statistics
async function loadStats() {
  chrome.runtime.sendMessage({ action: 'getStats' }, (stats) => {
    if (stats) {
      document.getElementById('urlsScanned').textContent = stats.urlsScanned.toLocaleString();
      document.getElementById('threatsBlocked').textContent = stats.threatsBlocked.toLocaleString();
      document.getElementById('phishingBlocked').textContent = stats.phishingBlocked.toLocaleString();
      document.getElementById('malwareBlocked').textContent = stats.malwareBlocked.toLocaleString();
    }
  });
}

// Load settings
async function loadSettings() {
  const settings = await chrome.storage.sync.get({
    enabled: true,
    blockPhishing: true,
    blockMalware: true,
  });
  
  document.getElementById('protectionToggle').checked = settings.enabled;
  document.getElementById('phishingToggle').checked = settings.blockPhishing;
  document.getElementById('malwareToggle').checked = settings.blockMalware;
  
  updateStatus(settings.enabled);
}

// Save settings
async function saveSettings() {
  const settings = {
    enabled: document.getElementById('protectionToggle').checked,
    blockPhishing: document.getElementById('phishingToggle').checked,
    blockMalware: document.getElementById('malwareToggle').checked,
  };
  
  await chrome.storage.sync.set(settings);
  updateStatus(settings.enabled);
}

// Update status display
function updateStatus(enabled) {
  const statusIcon = document.getElementById('statusIcon');
  const statusText = document.getElementById('statusText');
  const statusSubtext = document.getElementById('statusSubtext');
  
  if (enabled) {
    statusIcon.className = 'status-icon protected';
    statusIcon.textContent = '🛡️';
    statusText.textContent = "You're Protected";
    statusSubtext.textContent = 'Real-time protection is active';
  } else {
    statusIcon.className = 'status-icon warning';
    statusIcon.textContent = '⚠️';
    statusText.textContent = 'Protection Disabled';
    statusSubtext.textContent = 'Enable protection to stay safe';
  }
}

// Scan current page
async function scanCurrentPage() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    const scanBtn = document.getElementById('scanBtn');
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span>⏳</span><span>Scanning...</span>';
    
    chrome.runtime.sendMessage({ action: 'checkUrl', url: tab.url }, (result) => {
      scanBtn.disabled = false;
      scanBtn.innerHTML = '<span>🔍</span><span>Scan Current Page</span>';
      
      if (result.malicious) {
        alert(`⚠️ Warning: This site has been flagged as ${result.type}!\n\nThreat Score: ${result.score}/10\nSources: ${result.sources?.length || 0}`);
      } else {
        alert('✅ This page appears to be safe.');
      }
    });
  }
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadSettings();
  
  // Auto-refresh stats every 2 seconds
  setInterval(loadStats, 2000);
  
  // Settings toggles
  document.getElementById('protectionToggle').addEventListener('change', saveSettings);
  document.getElementById('phishingToggle').addEventListener('change', saveSettings);
  document.getElementById('malwareToggle').addEventListener('change', saveSettings);
  
  // Scan button
  document.getElementById('scanBtn').addEventListener('click', scanCurrentPage);
  
  // Dashboard link
  document.getElementById('dashboardLink').addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: 'http://localhost:3002' });
  });
});
