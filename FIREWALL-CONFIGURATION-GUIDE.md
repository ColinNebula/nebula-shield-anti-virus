# 🔥 Application-Level Firewall Configuration Guide

## Quick Reference

### ✅ Now Working - Full Configuration Available!

The application-level firewall is now fully configurable with 20+ REST API endpoints for complete control.

---

## 🚀 Getting Started

### 1. Check Firewall Status

```javascript
const response = await fetch('http://localhost:3002/api/firewall/status');
const data = await response.json();

console.log('Firewall enabled:', data.status.enabled);
console.log('Windows Firewall:', data.status.windowsFirewall);
console.log('Platform:', data.status.platform);
console.log('Statistics:', data.status.statistics);
```

### 2. Start Firewall Monitoring

```javascript
await fetch('http://localhost:3002/api/firewall/start', {
  method: 'POST'
});
```

### 3. View All Rules

```javascript
const response = await fetch('http://localhost:3002/api/firewall/rules');
const data = await response.json();

console.log('Total rules:', data.count);
console.log('Rules:', data.rules);
```

---

## 📋 Complete API Endpoints

### Firewall Control

#### Get Status
```http
GET /api/firewall/status
```

#### Start Monitoring
```http
POST /api/firewall/start
```

#### Stop Monitoring
```http
POST /api/firewall/stop
```

#### Get Statistics
```http
GET /api/firewall/statistics
```

#### Reset Statistics
```http
POST /api/firewall/statistics/reset
```

---

### Rule Management

#### Get All Rules
```http
GET /api/firewall/rules
```

#### Get Single Rule
```http
GET /api/firewall/rules/:id
```

#### Create Rule
```http
POST /api/firewall/rules
Content-Type: application/json

{
  "rule": {
    "name": "Block Suspicious Port",
    "type": "port",
    "action": "block",
    "direction": "inbound",
    "protocol": "tcp",
    "ports": [4444, 5555],
    "enabled": true,
    "priority": 2,
    "description": "Block common malware ports"
  }
}
```

#### Update Rule
```http
PUT /api/firewall/rules/:id
Content-Type: application/json

{
  "updates": {
    "enabled": false,
    "priority": 5
  }
}
```

#### Delete Rule
```http
DELETE /api/firewall/rules/:id
```

#### Toggle Rule On/Off
```http
PATCH /api/firewall/rules/:id/toggle
```

---

### IP Management

#### Get Blocked IPs
```http
GET /api/firewall/blocked-ips
```

#### Block IP
```http
POST /api/firewall/block-ip
Content-Type: application/json

{
  "ip": "192.168.1.100",
  "reason": "Suspicious activity detected"
}
```

#### Unblock IP
```http
POST /api/firewall/unblock-ip
Content-Type: application/json

{
  "ip": "192.168.1.100"
}
```

---

### Application Control

#### Block Application
```http
POST /api/firewall/block-application
Content-Type: application/json

{
  "program": "C:\\Program Files\\SuspiciousApp\\app.exe",
  "ruleName": "Block Suspicious App"
}
```

#### Block Port
```http
POST /api/firewall/block-port
Content-Type: application/json

{
  "port": 3389,
  "protocol": "tcp",
  "direction": "in",
  "ruleName": "Block RDP"
}
```

---

### Windows Firewall Integration

#### Get Windows Firewall Rules
```http
GET /api/firewall/windows/rules
```

#### Add Windows Firewall Rule
```http
POST /api/firewall/windows/rules
Content-Type: application/json

{
  "ruleName": "Block Outbound to 192.168.1.50",
  "config": {
    "direction": "out",
    "action": "block",
    "protocol": "tcp",
    "remoteIP": "192.168.1.50"
  }
}
```

#### Remove Windows Firewall Rule
```http
DELETE /api/firewall/windows/rules/:name
```

---

### Threat Monitoring

#### Get Threat Log
```http
GET /api/firewall/threats?limit=100
```

#### Clear Threat Log
```http
DELETE /api/firewall/threats
```

#### Inspect Packet (Testing)
```http
POST /api/firewall/inspect
Content-Type: application/json

{
  "packet": {
    "sourceIP": "192.168.1.100",
    "destIP": "8.8.8.8",
    "sourcePort": 54321,
    "destPort": 443,
    "protocol": "tcp",
    "direction": "outbound"
  }
}
```

---

## 🎯 Common Configuration Examples

### Example 1: Block All Traffic from Specific IP

```javascript
await fetch('http://localhost:3002/api/firewall/block-ip', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    ip: '203.0.113.50',
    reason: 'Known malicious IP'
  })
});
```

### Example 2: Create Custom Port Blocking Rule

```javascript
await fetch('http://localhost:3002/api/firewall/rules', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    rule: {
      name: 'Block Torrent Ports',
      type: 'port',
      action: 'block',
      direction: 'both',
      protocol: 'tcp',
      ports: [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889],
      enabled: true,
      priority: 3,
      description: 'Block common BitTorrent ports'
    }
  })
});
```

### Example 3: Block Application from Accessing Network

```javascript
await fetch('http://localhost:3002/api/firewall/block-application', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    program: 'C:\\Program Files\\UnwantedApp\\app.exe',
    ruleName: 'Block UnwantedApp Internet Access'
  })
});
```

### Example 4: Create Rate Limiting Rule

```javascript
await fetch('http://localhost:3002/api/firewall/rules', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    rule: {
      name: 'Rate Limit HTTP',
      type: 'rate_limit',
      action: 'rate_limit',
      direction: 'inbound',
      protocol: 'tcp',
      ports: [80, 443],
      maxConnections: 100,
      timeWindow: 60,
      enabled: true,
      priority: 4,
      description: 'Prevent HTTP flood attacks'
    }
  })
});
```

### Example 5: Create Domain Blocking Rule

```javascript
await fetch('http://localhost:3002/api/firewall/rules', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    rule: {
      name: 'Block Malware Domains',
      type: 'domain',
      action: 'block',
      direction: 'outbound',
      protocol: 'any',
      domains: [
        'malicious-site.com',
        'phishing-site.net',
        'c2-server.org'
      ],
      enabled: true,
      priority: 1,
      description: 'Block known malware callback domains'
    }
  })
});
```

---

## 📊 Rule Types

| Type | Description | Example |
|------|-------------|---------|
| `port` | Port-based filtering | Block ports 4444, 5555 |
| `ip` | IP address filtering | Block 192.168.1.100 |
| `domain` | Domain name filtering | Block malware.com |
| `pattern` | Pattern matching | Block mining protocols |
| `rate_limit` | Connection rate limiting | Max 10 connections/min |
| `geo` | Geographic filtering | Block traffic from specific countries |

---

## 🔧 Rule Configuration Options

### Required Fields
- `name`: Rule display name
- `type`: Rule type (port, ip, domain, pattern, rate_limit, geo)
- `action`: Action to take (allow, block, rate_limit)
- `direction`: Traffic direction (inbound, outbound, both)
- `protocol`: Protocol (tcp, udp, icmp, any)

### Optional Fields
- `enabled`: Enable/disable rule (default: true)
- `priority`: Rule priority 1-10 (lower = higher priority)
- `description`: Rule description
- `ports`: Array of port numbers
- `domains`: Array of domain names
- `pattern`: RegEx pattern for matching
- `maxConnections`: For rate limiting
- `timeWindow`: Time window in seconds
- `countries`: Array of country codes for geo-blocking

---

## 📈 Statistics Response

```json
{
  "success": true,
  "statistics": {
    "packetsInspected": 45230,
    "threatsBlocked": 234,
    "allowedConnections": 44996,
    "droppedPackets": 234,
    "ruleHits": {
      "rule_001": 45,
      "rule_002": 123,
      "rule_003": 35000
    },
    "blockedIPsCount": 12,
    "allowedIPsCount": 5,
    "rulesCount": 10,
    "activeRulesCount": 8
  }
}
```

---

## 🛡️ Default Pre-configured Rules

1. **Block Tor Exit Nodes** - Blocks connections from Tor network
2. **Block C2 Servers** - Blocks command & control communications
3. **Allow HTTP/HTTPS** - Permits standard web traffic
4. **Block Cryptocurrency Mining** - Blocks mining pool connections
5. **Rate Limit SSH** - Prevents SSH brute force (5 attempts/5min)
6. **Rate Limit RDP** - Prevents RDP brute force (3 attempts/10min)
7. **Block Malware Domains** - Blocks known malware callbacks
8. **Allow DNS** - Permits DNS queries
9. **Block NetBIOS/SMB** - Prevents WannaCry-style attacks
10. **Geo-Block High-Risk** - Blocks specific countries (optional)

---

## 🔍 Monitoring & Logging

### Real-time Threat Detection

All blocked connections are logged with:
- Source/Destination IP
- Port numbers
- Protocol
- Matched rule
- Timestamp
- Threat severity

### Access Threat Log

```javascript
const response = await fetch('http://localhost:3002/api/firewall/threats?limit=50');
const data = await response.json();

data.threats.forEach(threat => {
  console.log(`[${threat.severity}] ${threat.type}: ${threat.reason}`);
  console.log(`  Source: ${threat.sourceIP}:${threat.port}`);
  console.log(`  Rule: ${threat.rule}`);
  console.log(`  Time: ${threat.timestamp}`);
});
```

---

## 🎨 Integration with Frontend

```javascript
import { useState, useEffect } from 'react';
import io from 'socket.io-client';

function FirewallControl() {
  const [rules, setRules] = useState([]);
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState({});

  useEffect(() => {
    // Load initial data
    loadRules();
    loadThreats();
    loadStats();

    // Real-time updates (if Socket.IO events added)
    const socket = io('http://localhost:3002');
    
    socket.on('firewall:threat-blocked', (data) => {
      setThreats(prev => [data, ...prev]);
    });

    return () => socket.disconnect();
  }, []);

  const loadRules = async () => {
    const res = await fetch('http://localhost:3002/api/firewall/rules');
    const data = await res.json();
    setRules(data.rules);
  };

  const toggleRule = async (ruleId) => {
    await fetch(`http://localhost:3002/api/firewall/rules/${ruleId}/toggle`, {
      method: 'PATCH'
    });
    loadRules();
  };

  return (
    <div>
      <h2>Firewall Rules</h2>
      {rules.map(rule => (
        <div key={rule.id}>
          <span>{rule.name}</span>
          <button onClick={() => toggleRule(rule.id)}>
            {rule.enabled ? 'Disable' : 'Enable'}
          </button>
        </div>
      ))}
    </div>
  );
}
```

---

## ⚡ Performance Tips

1. **Rule Priority**: Keep high-priority rules (1-2) for critical blocks
2. **Regular Cleanup**: Clear threat logs periodically
3. **Disable Unused Rules**: Improve performance by disabling unnecessary rules
4. **Monitor Statistics**: Watch for unusual patterns
5. **Use Rate Limiting**: Prevent resource exhaustion attacks

---

## 🐛 Troubleshooting

### Issue: Rules Not Taking Effect
- Check if rule is enabled: `GET /api/firewall/rules/:id`
- Verify monitoring is started: `POST /api/firewall/start`
- Check rule priority (lower number = higher priority)

### Issue: Windows Firewall Integration Not Working
- Verify running as Administrator
- Check Windows Firewall is enabled: `GET /api/firewall/status`
- Test with PowerShell: `netsh advfirewall show allprofiles`

### Issue: High False Positives
- Review threat log: `GET /api/firewall/threats`
- Adjust rule priorities
- Add allow rules for legitimate traffic
- Use whitelist IPs when needed

---

## ✅ Configuration Complete!

You now have full control over:
- ✅ Application-level firewall rules
- ✅ IP blocking/allowing
- ✅ Port filtering
- ✅ Application blocking
- ✅ Rate limiting
- ✅ Domain blocking
- ✅ Windows Firewall integration
- ✅ Real-time threat monitoring
- ✅ Comprehensive statistics

**All 20+ endpoints are ready to use!** 🎉
