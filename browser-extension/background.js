/**
 * Nebula Shield Browser Extension - Background Service Worker
 * Real-time web protection and threat detection
 */

const API_BASE_URL = 'http://localhost:8080/api';
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// Threat database cache
let threatCache = {
  urls: new Map(),
  domains: new Map(),
  ips: new Map(),
  lastUpdate: 0,
};

// Statistics
let stats = {
  urlsScanned: 0,
  threatsBlocked: 0,
  phishingBlocked: 0,
  malwareBlocked: 0,
};

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('Nebula Shield Web Protection installed');
  initializeThreatDatabase();
  loadSettings();
  
  // Set up alarm for periodic updates
  chrome.alarms.create('updateThreats', { periodInMinutes: 30 });
});

// Handle alarm events
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'updateThreats') {
    updateThreatDatabase();
  }
});

// Initialize threat database
async function initializeThreatDatabase() {
  try {
    const response = await fetch(`${API_BASE_URL}/threat-intel/initialize`);
    const data = await response.json();
    console.log('Threat database initialized:', data);
    await updateThreatDatabase();
  } catch (error) {
    console.error('Failed to initialize threat database:', error);
  }
}

// Update threat database from backend
async function updateThreatDatabase() {
  try {
    const response = await fetch(`${API_BASE_URL}/browser-extension/threats`);
    const data = await response.json();
    
    if (data.success) {
      // Update cache
      data.maliciousUrls?.forEach(url => {
        threatCache.urls.set(url, { malicious: true, type: 'malware' });
      });
      
      data.phishingUrls?.forEach(url => {
        threatCache.urls.set(url, { malicious: true, type: 'phishing' });
      });
      
      data.maliciousDomains?.forEach(domain => {
        threatCache.domains.set(domain, { malicious: true });
      });
      
      threatCache.lastUpdate = Date.now();
      console.log('Threat database updated:', {
        urls: threatCache.urls.size,
        domains: threatCache.domains.size,
      });
    }
  } catch (error) {
    console.error('Failed to update threat database:', error);
  }
}

// Load settings
async function loadSettings() {
  const settings = await chrome.storage.sync.get({
    enabled: true,
    blockPhishing: true,
    blockMalware: true,
    showWarnings: true,
  });
  return settings;
}

// Check URL safety
async function checkUrl(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    // Check cache first
    if (threatCache.urls.has(url)) {
      return threatCache.urls.get(url);
    }
    
    if (threatCache.domains.has(domain)) {
      return threatCache.domains.get(domain);
    }
    
    // Check with backend
    const response = await fetch(`${API_BASE_URL}/browser-extension/check-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    
    const result = await response.json();
    
    // Cache result
    if (result.malicious) {
      threatCache.urls.set(url, result);
    }
    
    return result;
  } catch (error) {
    console.error('URL check failed:', error);
    return { safe: true, error: error.message };
  }
}

// Analyze page content for phishing indicators
function analyzePageContent(content) {
  const indicators = {
    suspiciousKeywords: [
      'verify account', 'confirm identity', 'suspended account',
      'unusual activity', 'click here immediately', 'urgent action required',
      'update payment', 'confirm password', 'security alert',
    ],
    urgentLanguage: [
      'act now', 'limited time', 'expires today', 'immediate action',
      'verify now', 'account will be closed',
    ],
    financialKeywords: [
      'social security', 'credit card', 'bank account', 'routing number',
      'pin number', 'password', 'tax refund',
    ],
  };
  
  let score = 0;
  const findings = [];
  
  const lowerContent = content.toLowerCase();
  
  // Check for suspicious keywords
  indicators.suspiciousKeywords.forEach(keyword => {
    if (lowerContent.includes(keyword)) {
      score += 2;
      findings.push(`Suspicious keyword: "${keyword}"`);
    }
  });
  
  // Check for urgent language
  indicators.urgentLanguage.forEach(keyword => {
    if (lowerContent.includes(keyword)) {
      score += 1.5;
      findings.push(`Urgent language: "${keyword}"`);
    }
  });
  
  // Check for financial keywords
  indicators.financialKeywords.forEach(keyword => {
    if (lowerContent.includes(keyword)) {
      score += 1;
      findings.push(`Financial keyword: "${keyword}"`);
    }
  });
  
  // Check for excessive form inputs
  const inputCount = (content.match(/<input/gi) || []).length;
  if (inputCount > 5) {
    score += 2;
    findings.push(`Excessive form inputs: ${inputCount}`);
  }
  
  // Check for obfuscated links
  if (content.includes('javascript:') || content.includes('data:text/html')) {
    score += 3;
    findings.push('Obfuscated links detected');
  }
  
  return {
    score,
    findings,
    isPhishing: score >= 5,
    riskLevel: score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low',
  };
}

// Web request listener
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    stats.urlsScanned++;
    
    const settings = await loadSettings();
    if (!settings.enabled) return;
    
    const url = details.url;
    const result = await checkUrl(url);
    
    if (result.malicious) {
      if (result.type === 'phishing' && settings.blockPhishing) {
        stats.phishingBlocked++;
        stats.threatsBlocked++;
        
        // Show notification
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: 'Phishing Site Blocked',
          message: `Nebula Shield blocked a phishing attempt: ${new URL(url).hostname}`,
        });
        
        // Redirect to warning page
        return {
          redirectUrl: chrome.runtime.getURL('warning.html') + '?url=' + encodeURIComponent(url) + '&type=phishing',
        };
      }
      
      if (result.type === 'malware' && settings.blockMalware) {
        stats.malwareBlocked++;
        stats.threatsBlocked++;
        
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: 'Malware Site Blocked',
          message: `Nebula Shield blocked a malware site: ${new URL(url).hostname}`,
        });
        
        return {
          redirectUrl: chrome.runtime.getURL('warning.html') + '?url=' + encodeURIComponent(url) + '&type=malware',
        };
      }
    }
  },
  { urls: ['<all_urls>'] },
  ['blocking']
);

// Message handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Helper to handle async responses with timeout
  const handleAsync = (promise, timeoutMs = 5000) => {
    let responded = false;
    const timeoutId = setTimeout(() => {
      if (!responded) {
        responded = true;
        sendResponse({ error: 'Request timeout' });
      }
    }, timeoutMs);
    
    promise
      .then(result => {
        clearTimeout(timeoutId);
        if (!responded) {
          responded = true;
          sendResponse(result || { success: true });
        }
      })
      .catch(error => {
        clearTimeout(timeoutId);
        if (!responded) {
          responded = true;
          sendResponse({ error: error.message || 'Unknown error' });
        }
      });
  };

  if (request.action === 'checkUrl') {
    handleAsync(checkUrl(request.url));
    return true;
  }
  
  if (request.action === 'analyzeContent') {
    try {
      const analysis = analyzePageContent(request.content || '');
      sendResponse(analysis);
    } catch (error) {
      sendResponse({ error: error.message || 'Analysis failed' });
    }
    return false;
  }
  
  if (request.action === 'getStats') {
    sendResponse(stats);
    return false;
  }
  
  if (request.action === 'reportPhishing') {
    handleAsync(reportPhishing(request.url, request.details));
    return true;
  }
  
  // Default: Don't return true unless we're sending async response
  sendResponse({ error: 'Unknown action: ' + request.action });
  return false;
});

// Report phishing to backend
async function reportPhishing(url, details) {
  try {
    const response = await fetch(`${API_BASE_URL}/browser-extension/report-phishing`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, details, timestamp: Date.now() }),
    });
    
    const result = await response.json();
    
    if (result.success) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: 'Phishing Reported',
        message: 'Thank you for reporting this phishing attempt.',
      });
    }
    
    return result;
  } catch (error) {
    console.error('Failed to report phishing:', error);
    return { success: false, error: error.message };
  }
}

// Tab update listener for real-time scanning
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    checkUrl(tab.url).then(result => {
      if (result.malicious) {
        chrome.action.setBadgeText({ text: '!', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#F44336', tabId });
      } else {
        chrome.action.setBadgeText({ text: '', tabId });
      }
    });
  }
});

console.log('Nebula Shield background service worker loaded');
