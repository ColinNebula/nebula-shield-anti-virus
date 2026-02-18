# Web Protection Quick Reference

## Quick Start

### Enable Web Shield
```typescript
// Settings → Protection → Web Shield toggle
// Or programmatically:
await AsyncStorage.setItem('web_shield_enabled', 'true');
```

### Open URLs Safely
```typescript
import SafeBrowsingService from '../services/SafeBrowsingService';

// Instead of Linking.openURL():
SafeBrowsingService.openUrlSafely('https://example.com');
```

### Check URL Manually
```typescript
const result = await SafeBrowsingService.checkUrl('https://example.com');
if (result.malicious) {
  console.log(`Threat detected: ${result.type}, Score: ${result.score}/100`);
}
```

## Components

### WebProtectionScreen
- **Location**: `mobile/src/screens/WebProtectionScreen.tsx`
- **Tab**: "Web Shield" in bottom navigation
- **Features**:
  - Protection status dashboard
  - Statistics (URLs checked, threats blocked)
  - Manual URL checker
  - Browser history scanner
  - Recent activity viewer

### Settings Toggle
- **Location**: Settings → Protection → Web Shield
- **Storage**: AsyncStorage key `'web_shield_enabled'`
- **Default**: `true` (enabled)

## SafeBrowsingService API

### Main Methods

```typescript
// Check if enabled
const enabled = await SafeBrowsingService.isWebShieldEnabled();

// Open URL with protection
await SafeBrowsingService.openUrlSafely(url);

// Check URL safety
const result = await SafeBrowsingService.checkUrl(url);

// Report phishing
await SafeBrowsingService.reportPhishing(url, description);

// Report false positive
await SafeBrowsingService.reportFalsePositive(url);

// Get statistics
const stats = await SafeBrowsingService.getStatistics();

// Scan browser history
const scanResult = await SafeBrowsingService.scanBrowserHistory();
```

## Backend API Endpoints

```
GET    /api/browser-extension/threats           - Get threat database
POST   /api/browser-extension/check-url         - Check URL safety
POST   /api/browser-extension/report-phishing   - Report phishing
POST   /api/browser-extension/report-false-positive - Report false positive
GET    /api/browser-extension/statistics        - Get statistics
```

## Risk Levels

```typescript
type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';

// Colors
safe: '#4caf50'      // Green
low: '#ffc107'       // Amber
medium: '#ff9800'    // Orange
high: '#f44336'      // Red
critical: '#d32f2f'  // Dark Red
```

## Threat Types

- `'safe'` - No threat detected (score: 10)
- `'malware'` - Malicious software (score: 95)
- `'phishing'` - Fake/fraudulent site (score: 90)
- `'malware domain'` - C&C server/cryptominer (score: 98)

## Response Format

### URL Check Response
```typescript
{
  success: boolean;
  url: string;
  domain: string;
  malicious: boolean;
  type: string;           // 'safe' | 'malware' | 'phishing' | 'malware domain'
  score: number;          // 0-100 risk score
  sources: string[];      // Detection sources
  timestamp: string;
}
```

### Statistics Response
```typescript
{
  success: boolean;
  statistics: {
    totalUrls: number;
    maliciousCount: number;
    phishingCount: number;
    malwareDomainsCount: number;
    lastUpdate: string;
  }
}
```

## Common Patterns

### Pattern 1: Protected Link in Component
```typescript
import SafeBrowsingService from '../services/SafeBrowsingService';

<Button onPress={() => SafeBrowsingService.openUrlSafely('https://example.com')}>
  Visit Website
</Button>
```

### Pattern 2: Custom Handling
```typescript
const openLink = async (url: string) => {
  const result = await SafeBrowsingService.checkUrl(url);
  
  if (result.malicious) {
    // Custom alert or UI
    console.warn(`Blocked: ${url} - ${result.type}`);
  } else {
    Linking.openURL(url);
  }
};
```

### Pattern 3: Conditional Protection
```typescript
const webShieldEnabled = await SafeBrowsingService.isWebShieldEnabled();

if (webShieldEnabled) {
  await SafeBrowsingService.openUrlSafely(url);
} else {
  Linking.openURL(url);
}
```

## Styling

### Theme Colors
```typescript
const theme = useTheme();

// Backgrounds
backgroundColor: theme.colors.background
backgroundColor: theme.colors.surface

// Text
color: theme.colors.onSurface
color: theme.colors.onSurfaceVariant

// Icons by threat level
const getRiskColor = (level: string) => {
  switch (level) {
    case 'critical': return '#d32f2f';
    case 'high': return '#f44336';
    case 'medium': return '#ff9800';
    case 'low': return '#ffc107';
    case 'safe': default: return '#4caf50';
  }
};
```

## Error Handling

### Network Errors
```typescript
// SafeBrowsingService handles errors gracefully
// Fails open (allows URL) if backend unreachable
try {
  await SafeBrowsingService.openUrlSafely(url);
} catch (error) {
  // Fallback: open URL anyway
  Linking.openURL(url);
}
```

### API Timeout
- Default timeout: 5000ms (5 seconds)
- On timeout: URL is allowed (fail-open)
- Error logged to console

## Testing

### Test Malicious URLs
```typescript
// These URLs are in the threat database:
SafeBrowsingService.openUrlSafely('https://evil-site.com');
SafeBrowsingService.openUrlSafely('https://paypal-verify.tk');
SafeBrowsingService.openUrlSafely('https://cryptominer.io');
```

### Test Safe URLs
```typescript
SafeBrowsingService.openUrlSafely('https://google.com');
SafeBrowsingService.openUrlSafely('https://github.com');
```

### Manual Check
```typescript
const result = await SafeBrowsingService.checkUrl('https://test.com');
console.log(JSON.stringify(result, null, 2));
```

## Performance Tips

1. **Use openUrlSafely() for all external links** - Automatic protection
2. **Cache threat database locally** - Reduce API calls
3. **Implement request debouncing** - For rapid URL checks
4. **Use async/await** - Non-blocking UI
5. **Show loading states** - Better UX during checks

## Security Best Practices

1. ✅ Always use `SafeBrowsingService.openUrlSafely()` for external links
2. ✅ Enable Web Shield by default
3. ✅ Warn users when disabling protection
4. ✅ Log blocked threats for analytics
5. ✅ Update threat database regularly
6. ❌ Don't store browsing history on server
7. ❌ Don't bypass protection without user consent
8. ❌ Don't hardcode API URLs (use environment variables)

## Migration Guide

### Before
```typescript
import { Linking } from 'react-native';

<Button onPress={() => Linking.openURL('https://example.com')}>
  Open Link
</Button>
```

### After
```typescript
import SafeBrowsingService from '../services/SafeBrowsingService';

<Button onPress={() => SafeBrowsingService.openUrlSafely('https://example.com')}>
  Open Link
</Button>
```

## Debugging

### Enable Verbose Logging
```typescript
// In SafeBrowsingService.ts
console.log('Checking URL:', url);
console.log('Result:', result);
console.log('Web Shield Status:', enabled);
```

### Test Backend Connection
```bash
# Test threat database
curl http://10.0.0.72:8080/api/browser-extension/threats

# Test URL check
curl -X POST -H "Content-Type: application/json" \
  -d '{"url":"https://google.com"}' \
  http://10.0.0.72:8080/api/browser-extension/check-url

# Test statistics
curl http://10.0.0.72:8080/api/browser-extension/statistics
```

### Check AsyncStorage
```typescript
const status = await AsyncStorage.getItem('web_shield_enabled');
console.log('Web Shield:', status);
```

## Resources

- **Full Documentation**: `BROWSER_PROTECTION_GUIDE.md`
- **Backend Code**: `backend/auth-server.js` (lines 1383-1554)
- **Frontend Component**: `mobile/src/screens/WebProtectionScreen.tsx`
- **Service Layer**: `mobile/src/services/SafeBrowsingService.ts`
- **Settings Integration**: `mobile/src/screens/SettingsScreen.tsx`

---

**Last Updated**: November 5, 2025
