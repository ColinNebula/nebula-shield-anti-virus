# 🌐 Nebula Shield Browser Extension

Real-time web protection and phishing detection for Chrome and Firefox.

## Features

- 🛡️ **Real-time Protection** - Automatic threat detection on every page
- 🎣 **Phishing Detection** - AI-powered phishing site identification
- 🚫 **Malware Blocking** - Block access to known malware sites
- 🔍 **URL Scanning** - Check URL reputation before visiting
- 📊 **Statistics Dashboard** - Track scans and blocked threats
- 📝 **Community Reports** - Report phishing and false positives

## Installation

### Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right corner)
3. Click **Load unpacked**
4. Select the `browser-extension` folder
5. ✅ Extension installed!

### Firefox

1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Navigate to the `browser-extension` folder
4. Select `manifest.json`
5. ✅ Extension installed!

### Edge

Same process as Chrome (Edge uses Chromium).

## Files

```
browser-extension/
├── manifest.json      # Extension configuration
├── background.js      # Background service worker
├── content.js         # Content script (injected into pages)
├── popup.html         # Extension popup UI
├── popup.js           # Popup functionality
└── warning.html       # Threat warning page
```

## How It Works

### Background Service Worker (`background.js`)

Runs continuously to:
- Monitor web requests
- Check URLs against threat database
- Block malicious sites
- Update threat feeds
- Handle notifications

### Content Script (`content.js`)

Injected into every page to:
- Analyze page content
- Detect phishing patterns
- Monitor form submissions
- Show warning banners
- Prevent credential theft

### Popup (`popup.html`)

User interface showing:
- Protection status
- Statistics (URLs scanned, threats blocked)
- Quick page scan
- Settings toggles
- Dashboard link

## API Integration

### Backend Endpoints

```javascript
const API_BASE_URL = 'http://localhost:8080/api';

// Get threat database
GET /api/browser-extension/threats

// Check URL safety
POST /api/browser-extension/check-url
Body: { "url": "https://example.com" }

// Report phishing
POST /api/browser-extension/report-phishing
Body: { "url": "...", "details": {...} }

// Report false positive
POST /api/browser-extension/report-false-positive
Body: { "url": "..." }
```

## Threat Detection

### URL Checking

Checks against multiple sources:
- Nebula Shield threat database
- URLhaus malware database
- AbuseIPDB reputation
- Google Safe Browsing

### Content Analysis

Analyzes page content for:

**Suspicious Keywords:**
- "verify account"
- "confirm identity"
- "suspended account"
- "unusual activity"

**Urgent Language:**
- "act now"
- "limited time"
- "expires today"

**Financial Keywords:**
- "social security"
- "credit card"
- "bank account"

**Technical Indicators:**
- Excessive form inputs (>5)
- Obfuscated links
- JavaScript/data URIs

**Risk Scoring:**
- **Low** (0-3): Minimal indicators
- **Medium** (4-6): Some suspicious patterns
- **High** (7+): Multiple red flags → Phishing warning

## User Interface

### Popup Window

<img src="https://via.placeholder.com/400x600?text=Extension+Popup" width="200">

Features:
- Protection status (Protected/Disabled)
- Statistics counters
- Scan current page button
- Settings toggles:
  - Real-time Protection
  - Block Phishing
  - Block Malware
- Dashboard link

### Warning Page

When a threat is detected, users see:
- ⚠️ Large warning icon
- Threat type (Phishing/Malware)
- Blocked URL
- Explanation of threat
- Actions:
  - Go Back to Safety (recommended)
  - Report False Positive
  - Proceed Anyway (requires confirmation)

### In-page Warning Banner

For potential phishing:
- Red gradient banner at top of page
- Warning message
- Risk level (LOW/MEDIUM/HIGH)
- Details (expandable)
- Report Phishing button
- Dismiss button

## Settings

Stored in `chrome.storage.sync`:

```javascript
{
  "enabled": true,           // Real-time protection
  "blockPhishing": true,     // Block phishing sites
  "blockMalware": true,      // Block malware sites
  "showWarnings": true       // Show warning banners
}
```

## Statistics

Tracked metrics:
- `urlsScanned`: Total URLs checked
- `threatsBlocked`: Total threats blocked
- `phishingBlocked`: Phishing attempts blocked
- `malwareBlocked`: Malware sites blocked

## Development

### Local Testing

1. Start backend:
```bash
cd ../backend
node mock-backend.js
```

2. Load extension in browser (see Installation)

3. Test on various websites

4. Check console for logs:
```javascript
console.log('Nebula Shield: URL checked');
```

### Configuration

Edit `background.js`:
```javascript
const API_BASE_URL = 'http://localhost:8080/api';
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
```

### Testing Phishing Detection

Test URLs (examples):
- `http://test-phishing.example.com`
- Pages with suspicious keywords
- Forms requesting sensitive data

## Permissions Explained

```json
{
  "permissions": [
    "webRequest",        // Monitor web requests
    "webNavigation",     // Track page navigation
    "storage",           // Save settings
    "tabs",              // Access tab information
    "notifications",     // Show notifications
    "activeTab"          // Current tab access
  ],
  "host_permissions": [
    "<all_urls>"         // Check all websites
  ]
}
```

## Publishing

### Chrome Web Store

1. Create developer account ($5 fee)
2. Prepare assets:
   - 128x128 icon
   - Screenshots (1280x800)
   - Promotional images
3. Zip extension folder
4. Upload to Chrome Web Store Developer Dashboard
5. Fill in store listing
6. Submit for review

### Firefox Add-ons

1. Create account at addons.mozilla.org
2. Prepare assets (same as Chrome)
3. Zip extension folder
4. Upload to Add-on Developer Hub
5. Fill in listing details
6. Submit for review

## Security & Privacy

### Data Collection
- ✅ **NO** personal data collected
- ✅ **NO** browsing history stored
- ✅ **NO** data sold to third parties

### What We Store
- Protection settings (local only)
- Statistics counters (local only)
- Threat cache (temporary, 5 minutes)

### What We Send
- URLs (for reputation check)
- Phishing reports (anonymous)
- False positive reports (URL only)

### Encryption
- HTTPS for all API communication
- TLS 1.3 recommended
- Certificate validation

## Performance

- Memory: < 20MB
- CPU: Minimal (< 1%)
- Network: Only when checking URLs
- Cache: 5-minute expiration
- Background: Service worker (efficient)

## Troubleshooting

### Extension not working

1. Check if enabled in extensions page
2. Click extension icon → verify "Protected"
3. Check browser console for errors
4. Reload extension

### Not blocking threats

1. Verify "Real-time Protection" is ON
2. Update threat database
3. Check API connection:
```bash
curl http://localhost:8080/api/browser-extension/threats
```

### False positives

1. Click extension icon
2. Click "Report False Positive"
3. Site will be reviewed

### Performance issues

1. Clear extension cache
2. Reduce polling frequency
3. Disable unused features
4. Check for conflicting extensions

## Browser Compatibility

| Feature | Chrome | Firefox | Edge | Safari |
|---------|--------|---------|------|--------|
| Web Request API | ✅ | ✅ | ✅ | ⚠️ |
| Content Scripts | ✅ | ✅ | ✅ | ✅ |
| Background SW | ✅ | ✅ | ✅ | ⚠️ |
| Notifications | ✅ | ✅ | ✅ | ✅ |

⚠️ = Limited support or requires modification

## Advanced Features

### Custom Threat Patterns

Add custom phishing patterns in `content.js`:

```javascript
const customPatterns = [
  { 
    pattern: /your-keyword/i, 
    description: 'Custom indicator' 
  }
];
```

### Whitelist

To whitelist a domain:

```javascript
const whitelist = ['trusted-site.com'];
```

### Blacklist

To blacklist a domain:

```javascript
threatIntelligence.maliciousUrls.add('bad-site.com');
```

## Contributing

1. Fork repository
2. Create feature branch
3. Test on Chrome and Firefox
4. Submit pull request

## License

Part of Nebula Shield Anti-Virus Suite

## Support

For issues:
- Check [MULTI_PLATFORM_GUIDE.md](../MULTI_PLATFORM_GUIDE.md)
- Review API documentation
- Test with curl commands
- Check browser console

---

**Browse Safely! 🌐🛡️**
