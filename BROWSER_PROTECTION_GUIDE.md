# Web Protection & Safe Browsing Features

## Overview

Nebula Shield now includes comprehensive web protection to keep you safe while browsing. The Web Shield feature monitors browsing activity, blocks malicious sites, detects phishing attempts, and provides real-time URL scanning.

## Features

### 1. Web Protection Screen

A dedicated screen accessible from the bottom navigation bar that provides:

- **Protection Status Dashboard**: Shows whether Web Shield is active or disabled
- **Real-time Statistics**: 
  - Total URLs checked
  - Threats blocked
  - Phishing attempts blocked
  - Malware sites blocked
- **URL Safety Checker**: Manually check any URL before visiting
- **Browser History Scanner**: Scan browsing history for visited malicious sites
- **Recent Browsing Activity**: View recent sites visited and their safety status
- **Protection Features Overview**: List of active protection capabilities

### 2. Safe Browsing Feature

Real-time URL scanning that protects you automatically:

#### How It Works

1. **Automatic Protection**: When Web Shield is enabled, all URLs are checked before opening
2. **Threat Detection**: URLs are compared against our threat database containing:
   - Malicious URLs (malware, trojans, viruses)
   - Phishing sites (fake login pages, scams)
   - Malware domains (command & control servers, cryptominers)
3. **Risk Scoring**: Each URL receives a risk score from 0-100
4. **User Choice**: If a threat is detected, you can:
   - Cancel (recommended)
   - Visit anyway (at your own risk)
   - Report false positive (if the site is safe)

#### Integration

Use the `SafeBrowsingService` throughout your app:

```typescript
import SafeBrowsingService from '../services/SafeBrowsingService';

// Instead of using Linking.openURL directly:
// Linking.openURL('https://example.com');

// Use this for automatic protection:
SafeBrowsingService.openUrlSafely('https://example.com');
```

### 3. Browser History Scanner

Scan your browsing history to find previously visited malicious sites:

#### Features

- **One-Click Scanning**: Tap "Scan History" to analyze all visited sites
- **Threat Detection**: Identifies malicious sites you may have visited
- **Safety Report**: Shows scan results with threat counts
- **Last Scan Tracking**: Displays when history was last scanned

#### Limitations

- Mobile browser history access requires system-level permissions
- Full functionality available on desktop version
- Mobile version provides simulated scanning for demonstration

### 4. Web Shield Toggle

Control web protection from the Settings screen:

#### Location

Settings → Protection → Web Shield

#### Options

- **Enabled** (Default): All URLs are checked before opening
- **Disabled**: URLs open without safety checks (NOT recommended)

#### Behavior

When you toggle Web Shield:
- **Enabled**: Shows confirmation that protection is active
- **Disabled**: Shows warning about browsing without protection
- Setting persists across app restarts using AsyncStorage

## API Endpoints

### Backend Integration

The Web Protection feature uses these API endpoints:

#### 1. Get Threat Database
```
GET /api/browser-extension/threats
```

Returns lists of:
- Malicious URLs
- Phishing URLs  
- Malware domains
- Last update timestamp

#### 2. Check URL Safety
```
POST /api/browser-extension/check-url
Body: { url: string }
```

Returns:
- `malicious`: boolean
- `type`: 'safe' | 'malware' | 'phishing' | 'malware domain'
- `score`: Risk score 0-100
- `sources`: Detection sources

#### 3. Report Phishing
```
POST /api/browser-extension/report-phishing
Body: { url: string, description?: string }
```

Submit suspected phishing sites for review.

#### 4. Report False Positive
```
POST /api/browser-extension/report-false-positive
Body: { url: string, reason?: string }
```

Report incorrectly blocked sites.

#### 5. Get Statistics
```
GET /api/browser-extension/statistics
```

Returns threat database statistics.

## Implementation Details

### Files Created/Modified

#### New Files

1. **`mobile/src/screens/WebProtectionScreen.tsx`**
   - Main web protection UI
   - Statistics dashboard
   - URL checker interface
   - Browser history scanner
   - Recent activity viewer

2. **`mobile/src/services/SafeBrowsingService.ts`**
   - Core safe browsing logic
   - URL safety checking
   - Protected link opening
   - Phishing/false positive reporting
   - Statistics retrieval

3. **`BROWSER_PROTECTION_GUIDE.md`**
   - This documentation file

#### Modified Files

1. **`mobile/src/App.tsx`**
   - Added Web Protection tab to bottom navigation
   - Added web shield icon to tab bar
   - Imported WebProtectionScreen component

2. **`mobile/src/screens/SettingsScreen.tsx`**
   - Added Web Shield toggle in Protection section
   - AsyncStorage integration for persistence
   - Snackbar feedback on toggle

3. **`backend/auth-server.js`**
   - Added browser extension API endpoints
   - Threat database management
   - URL checking logic
   - Reporting endpoints

### State Management

Web Shield status is stored in AsyncStorage:
- Key: `'web_shield_enabled'`
- Values: `'true'` | `'false'`
- Default: `'true'` (enabled)

### Theme Support

All Web Protection UI components support light/dark themes:
- Dynamic backgrounds using `theme.colors.background`
- Surface colors for cards
- Text colors from theme
- Icon colors based on threat level

## User Guide

### Getting Started

1. **Enable Web Shield**
   - Go to Settings → Protection
   - Toggle "Web Shield" ON (enabled by default)

2. **View Protection Status**
   - Tap "Web Shield" tab in bottom navigation
   - Check your protection statistics
   - View recent browsing activity

3. **Check a URL Manually**
   - Open Web Shield screen
   - Enter URL in "Check URL Safety" card
   - Tap "Check URL" button
   - Review safety report

4. **Scan Browser History**
   - Open Web Shield screen
   - Find "Browser History Scan" card
   - Tap "Scan History" button
   - Wait for scan to complete
   - Review results

### Protection in Action

When you try to open a malicious link:

1. Web Shield intercepts the request
2. URL is checked against threat database
3. If malicious:
   - Alert appears with warning
   - Shows threat type and risk score
   - Options: Cancel, Visit Anyway, Report False Positive
4. If safe:
   - URL opens normally
   - No interruption

### Reporting

#### Report Phishing

If you encounter a suspicious site not yet blocked:
1. Use `SafeBrowsingService.reportPhishing(url)`
2. Optionally provide description
3. Submit report
4. Security team reviews submission

#### Report False Positive

If a safe site is incorrectly blocked:
1. Click "Report False Positive" in alert
2. Or use `SafeBrowsingService.reportFalsePositive(url)`
3. Provide reason (optional)
4. Submit report
5. Security team reviews and updates database

## Statistics Tracking

The Web Protection screen displays:

- **URLs Checked**: Total count of URLs scanned
- **Threats Blocked**: Number of malicious sites blocked
- **Phishing Blocked**: Phishing attempts prevented
- **Malware Blocked**: Malware sites blocked
- **Last Scan**: When browser history was last scanned

Statistics are retrieved from the backend API and updated on refresh.

## Security Considerations

### Fail-Open Design

If the backend is unreachable:
- URLs are allowed to open (fail-open)
- Ensures availability over security
- User can still browse if API is down
- Error is logged for debugging

### Privacy

- URLs are checked against local threat database
- No browsing history stored on server
- Reports are anonymized
- No tracking or analytics

### Performance

- URL checks timeout after 5 seconds
- Non-blocking UI (async checks)
- Minimal impact on user experience
- Efficient threat database lookups

## Future Enhancements

Planned features for upcoming releases:

1. **Browser Extension**
   - Chrome/Firefox/Edge extensions
   - Desktop browser integration
   - Real-time web page scanning
   - Form protection

2. **Enhanced History Scanning**
   - Native module for browser access
   - Deep history analysis
   - Scheduled automatic scans
   - Email reports

3. **Machine Learning**
   - AI-powered URL classification
   - Behavioral analysis
   - Zero-day threat detection
   - Reputation scoring

4. **Community Protection**
   - Crowdsourced threat intelligence
   - User voting on reports
   - Real-time threat sharing
   - Global threat map

5. **Advanced Features**
   - Safe search enforcement
   - Parental controls
   - Content filtering
   - Download protection

## Troubleshooting

### Web Shield Not Working

1. Check Settings → Protection → Web Shield is ON
2. Verify backend server is running (port 8080)
3. Check network connectivity to 10.0.0.72:8080
4. Review logs for API errors

### False Positives

If legitimate sites are being blocked:
1. Click "Report False Positive" in the alert
2. Or manually report via `SafeBrowsingService.reportFalsePositive()`
3. Wait for security team review (24-48 hours)
4. Temporarily disable Web Shield if urgent

### URL Checker Not Responding

1. Check backend server status
2. Verify API endpoint: `http://10.0.0.72:8080/api/browser-extension/check-url`
3. Test with curl: `curl -X POST -H "Content-Type: application/json" -d '{"url":"https://google.com"}' http://10.0.0.72:8080/api/browser-extension/check-url`
4. Check network firewall settings

## Developer Notes

### Adding SafeBrowsing to New Features

When adding clickable links to new screens:

```typescript
import SafeBrowsingService from '../services/SafeBrowsingService';

// DON'T do this:
<Button onPress={() => Linking.openURL('https://example.com')}>
  Visit Site
</Button>

// DO this:
<Button onPress={() => SafeBrowsingService.openUrlSafely('https://example.com')}>
  Visit Site
</Button>
```

### Customizing Threat Detection

To add new threat categories, edit `backend/auth-server.js`:

```javascript
const browserThreats = {
  maliciousUrls: [...],
  phishingUrls: [...],
  malwareDomains: [...],
  // Add new category:
  cryptominers: ['coinhive.com', 'crypto-loot.com'],
  lastUpdate: new Date().toISOString()
};
```

### Updating Threat Database

The threat database should be updated regularly:
1. Security team reviews reports
2. Adds confirmed threats to database
3. Removes false positives
4. Updates `lastUpdate` timestamp
5. Database syncs to clients on next check

## Support

For issues or questions:
- GitHub Issues: [nebula-shield-anti-virus/issues](https://github.com/ColinNebula/nebula-shield-anti-virus/issues)
- Email: support@nebulashield.com
- Documentation: See `DOCUMENTATION-INDEX.md`

---

**Last Updated**: November 5, 2025  
**Version**: 1.0.0  
**Component**: Mobile Web Protection
