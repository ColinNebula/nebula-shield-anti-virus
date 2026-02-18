/**
 * Nebula Shield Browser Extension - Content Script
 * Injected into all web pages for real-time protection
 */

(function() {
  'use strict';
  
  console.log('Nebula Shield content script loaded');
  
  // Analyze current page
  function analyzePage() {
    const content = document.body.innerText;
    
    chrome.runtime.sendMessage({
      action: 'analyzeContent',
      content: content,
    }, (response) => {
      if (response && response.isPhishing) {
        showPhishingWarning(response);
      }
    });
  }
  
  // Show phishing warning banner
  function showPhishingWarning(analysis) {
    const banner = document.createElement('div');
    banner.id = 'nebula-shield-warning';
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: linear-gradient(135deg, #F44336, #D32F2F);
      color: white;
      padding: 16px;
      z-index: 999999;
      box-shadow: 0 4px 8px rgba(0,0,0,0.3);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    `;
    
    banner.innerHTML = `
      <div style="max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between;">
        <div style="flex: 1;">
          <div style="display: flex; align-items: center; margin-bottom: 8px;">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="white" style="margin-right: 12px;">
              <path d="M12 2L1 21h22L12 2zm0 3.5L19.5 19h-15L12 5.5zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z"/>
            </svg>
            <strong style="font-size: 18px;">⚠️ Warning: Potential Phishing Site</strong>
          </div>
          <p style="margin: 0; opacity: 0.95; font-size: 14px;">
            Nebula Shield detected suspicious activity on this page (Risk: ${analysis.riskLevel.toUpperCase()})
          </p>
          <details style="margin-top: 8px; cursor: pointer;">
            <summary style="font-size: 13px; opacity: 0.9;">View details</summary>
            <ul style="margin: 8px 0 0 20px; font-size: 12px; opacity: 0.9;">
              ${analysis.findings.map(f => `<li>${f}</li>`).join('')}
            </ul>
          </details>
        </div>
        <div style="display: flex; gap: 12px; margin-left: 20px;">
          <button id="nebula-report-btn" style="
            background: white;
            color: #F44336;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
          ">Report Phishing</button>
          <button id="nebula-dismiss-btn" style="
            background: rgba(255,255,255,0.2);
            color: white;
            border: 2px solid white;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
          ">Dismiss</button>
        </div>
      </div>
    `;
    
    document.body.insertBefore(banner, document.body.firstChild);
    
    // Add event listeners
    document.getElementById('nebula-dismiss-btn').addEventListener('click', () => {
      banner.remove();
    });
    
    document.getElementById('nebula-report-btn').addEventListener('click', () => {
      chrome.runtime.sendMessage({
        action: 'reportPhishing',
        url: window.location.href,
        details: analysis,
      }, (response) => {
        if (response && response.success) {
          alert('Thank you for reporting this phishing attempt!');
          banner.remove();
        }
      });
    });
  }
  
  // Monitor form submissions for credential theft
  document.addEventListener('submit', (e) => {
    const form = e.target;
    const inputs = form.querySelectorAll('input[type="password"], input[type="email"], input[name*="password"], input[name*="email"]');
    
    if (inputs.length > 0) {
      // Check if current page is suspicious
      chrome.runtime.sendMessage({
        action: 'checkUrl',
        url: window.location.href,
      }, (result) => {
        if (result && result.malicious) {
          e.preventDefault();
          alert('⚠️ Nebula Shield blocked this form submission to protect your credentials from a potentially malicious site.');
        }
      });
    }
  });
  
  // Monitor for suspicious redirects
  let lastUrl = window.location.href;
  const observer = new MutationObserver(() => {
    if (window.location.href !== lastUrl) {
      lastUrl = window.location.href;
      
      chrome.runtime.sendMessage({
        action: 'checkUrl',
        url: window.location.href,
      });
    }
  });
  
  observer.observe(document, { subtree: true, childList: true });
  
  // Initial page analysis
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', analyzePage);
  } else {
    analyzePage();
  }
  
  // Monitor for dynamically added forms
  const formObserver = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeName === 'FORM' || (node.querySelector && node.querySelector('form'))) {
          analyzePage();
        }
      });
    });
  });
  
  formObserver.observe(document.body, { childList: true, subtree: true });
  
})();
