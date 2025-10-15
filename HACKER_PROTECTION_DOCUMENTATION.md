# 🛡️ Hacker Attack Protection Module

## Overview
The Hacker Attack Protection module provides comprehensive defense against sophisticated cyber attacks including DDoS, brute force, injection attacks, and more. It combines real-time monitoring, behavioral analysis, and automated response systems.

## Features

### 1. **DDoS Protection** 🌊
Detects and mitigates Distributed Denial of Service attacks.

**Detection Thresholds:**
- 100 requests/second → Immediate block (1 hour)
- 500 requests/minute → Block (30 minutes)
- 50 simultaneous connections → Alert

**How it works:**
- Tracks request rates per IP address
- Automatically blocks excessive traffic sources
- Logs all DDoS attempts with severity levels

**Example:**
```javascript
import { detectDDoS } from './services/hackerProtection';

const result = detectDDoS('45.142.212.61');
if (result.blocked) {
  console.log('DDoS attack blocked:', result.reason);
}
```

---

### 2. **Brute Force Protection** 🔒
Prevents password guessing attacks on login endpoints.

**Detection Rules:**
- 5 failed login attempts within 15 minutes → Block 30 minutes
- Tracks attempts per IP and username
- Auto-expires blocks after duration

**How it works:**
- Records all failed login attempts
- Analyzes patterns across time windows
- Blocks repeat offenders automatically

**Example:**
```javascript
import { detectBruteForce } from './services/hackerProtection';

const result = detectBruteForce('192.168.1.100', 'admin', false);
if (result.blocked) {
  console.log(`Blocked for ${result.blockedMinutes} minutes`);
}
```

---

### 3. **SQL Injection Detection** 💉
Identifies and blocks SQL injection attempts in user input.

**Detected Patterns:**
- `SELECT * FROM`, `UNION SELECT`
- `DROP TABLE`, `DELETE FROM`
- `exec sp_`, `'; --`, `1=1`
- URL-encoded injection attempts

**Example:**
```javascript
import { detectSQLInjection } from './services/hackerProtection';

const input = "admin' OR '1'='1";
const result = detectSQLInjection(input);
if (result.detected) {
  console.log('SQL Injection blocked:', result.type);
}
```

---

### 4. **XSS Attack Prevention** 🎭
Blocks Cross-Site Scripting attempts.

**Detected Patterns:**
- `<script>` tags and JavaScript injection
- `<iframe>` embeds
- `javascript:`, `vbscript:` protocols
- Event handlers (`onclick=`, `onerror=`)
- `eval()`, `expression()` functions

**Example:**
```javascript
import { detectXSS } from './services/hackerProtection';

const input = "<script>alert('XSS')</script>";
const result = detectXSS(input);
// Returns: { detected: true, type: 'XSS Attack' }
```

---

### 5. **Command Injection Detection** ⚡
Prevents OS command injection attacks.

**Detected Patterns:**
- Shell metacharacters: `;`, `|`, `&`, `` ` ``, `$()`
- Path traversal: `../`, `/etc/passwd`
- Dangerous commands: `wget`, `curl`, `nc`
- Binary paths: `/bin/sh`, `/bin/bash`

---

### 6. **Rate Limiting** ⏱️
Prevents API abuse and automated attacks.

**Limits:**
- 60 API calls per minute
- 1000 API calls per hour
- Automatic throttling on excess

**Example:**
```javascript
import { checkRateLimit } from './services/hackerProtection';

const result = checkRateLimit('192.168.1.100', '/api/users');
if (!result.allowed) {
  console.log(`Rate limited. Retry after ${result.retryAfter}s`);
}
```

---

### 7. **Honeypot System** 🍯
Decoy services that trap attackers.

**Active Honeypots:**
1. **Fake Admin Login** (`/admin/login`) - Catches unauthorized access
2. **Fake Database Port** (3306) - Detects port scanning
3. **Fake SSH Service** (22) - Traps brute force attempts
4. **Fake API Keys** (`/api/keys`) - Catches credential harvesting

**Behavior:**
- Any access to honeypot = Immediate 7-day block
- Logs attacker IP and attack pattern
- Helps identify reconnaissance attempts

---

### 8. **Geo-blocking** 🌍
Blocks traffic from specific countries.

**Blocked Countries (Example):**
- North Korea (KP)
- Iran (IR)
- Syria (SY)

**How it works:**
- IP geolocation lookup
- Automatic blocking based on country code
- 24-hour block duration

---

### 9. **Comprehensive Input Validation** ✅
All-in-one input security check.

**Example:**
```javascript
import { validateInput } from './services/hackerProtection';

const result = validateInput(userInput, clientIP, 'contact-form');
if (!result.valid) {
  console.log('Blocked threats:', result.threats);
  // IP automatically blocked for 2 hours
}
```

---

## Dashboard Features

### Real-time Monitoring 📊
- **Active Threats** - Last 5 minutes
- **Blocked IPs** - Currently blocked addresses
- **Honeypot Hits** - Trap activations
- **Rate Limited IPs** - Throttled clients

### 4 Main Tabs

#### Tab 1: Attack Log 📝
- Real-time attack attempts
- Severity levels (Critical, High, Medium, Low)
- IP addresses and timestamps
- Actions taken (blocked/rejected)

#### Tab 2: Blocked IPs 🚫
- Currently blocked IP addresses
- Block reasons and durations
- Remaining time before unblock
- Manual unblock option

#### Tab 3: Honeypots 🕵️
- Status of all decoy services
- Total hits per honeypot
- Last access timestamp
- Endpoint/port information

#### Tab 4: Statistics 📈
- Attacks by type (last 24h)
- Attacks by severity
- Top 10 attackers
- Block status tracking

---

## Protection Modules Status

All modules are **Active** by default:
- ✅ DDoS Protection
- ✅ Brute Force Shield
- ✅ Injection Detection
- ✅ Rate Limiting
- ✅ Geo-blocking
- ✅ Honeypot System

---

## API Reference

### Core Functions

#### `detectDDoS(ip, timestamp?)`
Checks if IP is performing DDoS attack.

**Returns:**
```javascript
{
  blocked: boolean,
  reason?: string,
  requestsPerSecond: number,
  requestsPerMinute: number
}
```

#### `detectBruteForce(ip, username, success, timestamp?)`
Tracks login attempts and blocks brute force.

**Returns:**
```javascript
{
  blocked: boolean,
  attempts: number,
  remaining?: number,
  blockedMinutes?: number
}
```

#### `validateInput(input, ip?, context?)`
Comprehensive security check for all injection types.

**Returns:**
```javascript
{
  valid: boolean,
  threats?: Array<{ type, pattern, input }>,
  action?: string
}
```

#### `blockIP(ip, reason, duration)`
Manually block an IP address.

**Parameters:**
- `ip`: IP address to block
- `reason`: Human-readable reason
- `duration`: Block duration in milliseconds

#### `isIPBlocked(ip)`
Check if IP is currently blocked.

**Returns:**
```javascript
{
  blocked: boolean,
  reason?: string,
  remainingMinutes?: number
}
```

#### `getSecurityDashboard()`
Get complete security dashboard data.

**Returns:**
```javascript
{
  realTimeStatus: {...},
  attackStats: {...},
  recentAttacks: [...],
  blockedIPs: [...],
  honeypots: [...],
  protectionStatus: {...}
}
```

---

## Configuration

### Thresholds (Customizable)

```javascript
const THRESHOLDS = {
  ddos: {
    requestsPerSecond: 100,    // Adjust for your traffic
    requestsPerMinute: 500,
    simultaneousConnections: 50
  },
  bruteForce: {
    maxFailedAttempts: 5,      // Login attempts
    timeWindowMinutes: 15,      // Time window
    blockDurationMinutes: 30    // Block duration
  },
  rateLimit: {
    apiCallsPerMinute: 60,     // API rate limit
    apiCallsPerHour: 1000
  }
};
```

### Blocked Countries

```javascript
const BLOCKED_COUNTRIES = ['KP', 'IR', 'SY'];
```

Add/remove country codes as needed (ISO 3166-1 alpha-2 format).

---

## Integration Examples

### Express.js Middleware

```javascript
import { detectDDoS, validateInput, checkRateLimit } from './hackerProtection';

app.use((req, res, next) => {
  const ip = req.ip;
  
  // Check DDoS
  const ddos = detectDDoS(ip);
  if (ddos.blocked) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  
  // Check rate limit
  const rateLimit = checkRateLimit(ip, req.path);
  if (!rateLimit.allowed) {
    return res.status(429).json({ 
      error: 'Rate limit exceeded',
      retryAfter: rateLimit.retryAfter 
    });
  }
  
  next();
});

// Validate POST data
app.post('/api/contact', (req, res) => {
  const validation = validateInput(req.body.message, req.ip, 'contact-form');
  
  if (!validation.valid) {
    return res.status(400).json({ 
      error: 'Invalid input',
      threats: validation.threats 
    });
  }
  
  // Process valid input...
});
```

### Login Endpoint Protection

```javascript
import { detectBruteForce } from './hackerProtection';

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;
  
  // Check brute force before validating credentials
  const bruteForce = detectBruteForce(ip, username, false);
  if (bruteForce.blocked) {
    return res.status(429).json({
      error: `Too many failed attempts. Try again in ${bruteForce.remainingMinutes} minutes`
    });
  }
  
  // Validate credentials
  const user = await authenticateUser(username, password);
  
  if (user) {
    // Success - clear failed attempts
    detectBruteForce(ip, username, true);
    return res.json({ token: generateToken(user) });
  } else {
    // Failed - record attempt
    detectBruteForce(ip, username, false);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
});
```

---

## Attack Log Format

Each attack is logged with:

```javascript
{
  id: number,
  type: string,              // 'DDoS', 'Brute Force', 'SQL Injection', etc.
  severity: string,          // 'Critical', 'High', 'Medium', 'Low'
  ip: string,
  details: string,           // Human-readable description
  action: string,            // 'IP Blocked', 'Request Rejected', etc.
  timestamp: string,         // ISO timestamp
  honeypot?: string          // If honeypot triggered
}
```

---

## Best Practices

### 1. **Monitor Regularly**
- Check attack log daily
- Review blocked IPs weekly
- Analyze attack patterns

### 2. **Adjust Thresholds**
- Start conservative
- Tune based on legitimate traffic
- Avoid false positives

### 3. **Whitelist Trusted IPs**
- Add known good IPs to allowlist
- Skip checks for internal networks
- Document all exceptions

### 4. **Update Patterns**
- Keep attack patterns current
- Add new threat signatures
- Follow security advisories

### 5. **Backup Logs**
- Export attack logs regularly
- Store for forensic analysis
- Comply with data retention policies

---

## Performance Impact

**Memory Usage:**
- ~2MB for 1000 tracked IPs
- ~1MB for 500 attack logs
- Auto-cleanup of old data

**CPU Impact:**
- <1ms per request check
- Regex matching is optimized
- Background cleanup every 5 minutes

**Recommendations:**
- Use Redis for distributed systems
- Implement connection pooling
- Cache geo-lookup results

---

## Troubleshooting

### Problem: Legitimate users getting blocked

**Solution:**
- Check attack log for false positives
- Adjust brute force thresholds
- Add IP to whitelist

### Problem: High memory usage

**Solution:**
- Reduce attack log retention (default: 500)
- Clear old rate limit data
- Implement log rotation

### Problem: Honeypot false alarms

**Solution:**
- Verify honeypot endpoints aren't linked
- Check for misconfigured crawlers
- Review honeypot access patterns

---

## Security Considerations

⚠️ **Important Notes:**

1. **Not a silver bullet** - Use in combination with other security measures
2. **Keep updated** - Attack patterns evolve constantly
3. **Test thoroughly** - Verify detection accuracy before production
4. **Legal compliance** - Ensure blocking complies with regulations
5. **Logging privacy** - IP addresses are personal data in some jurisdictions

---

## Sample Attack Data

The system includes 25 sample attacks for demonstration:
- DDoS attacks
- Brute force attempts
- SQL injection
- XSS attacks
- Port scanning
- Honeypot triggers

**To regenerate:**
```javascript
import { generateSampleAttacks } from './services/hackerProtection';
generateSampleAttacks();
```

---

## Future Enhancements

Planned features:
- [ ] Machine learning threat detection
- [ ] Advanced behavioral analysis
- [ ] Distributed honeypot network
- [ ] Real-time email alerts
- [ ] Integration with threat intelligence feeds
- [ ] Automated incident response
- [ ] SIEM integration
- [ ] Custom attack pattern creation UI

---

## Support

For issues or questions:
- Check attack log for details
- Review blocked IPs for patterns
- Consult troubleshooting guide
- Contact security team

---

## License

Part of Nebula Shield Anti-Virus System
© 2025 All Rights Reserved

---

**🛡️ Stay Protected!**
