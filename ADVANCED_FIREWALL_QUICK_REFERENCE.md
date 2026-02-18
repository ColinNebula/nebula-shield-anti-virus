# 🛡️ Advanced Firewall - Quick Reference Card

## 🚀 Quick Start

```powershell
# Start firewall monitoring
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/monitoring/start" -Method Post

# Get firewall statistics
$stats = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/statistics"
Write-Host "Threats blocked: $($stats.statistics.threatsBlocked)"
```

---

## 📋 Core Features

| Feature | Description | Endpoint |
|---------|-------------|----------|
| **DPI** | Deep Packet Inspection | `/api/firewall/dpi/detections` |
| **IDS** | Intrusion Detection | `/api/firewall/ids/alerts` |
| **IPS** | Intrusion Prevention | `/api/firewall/ips/blocks` |
| **App Filter** | Application Control | `/api/firewall/block-application` |
| **Geo-Blocker** | Country Blocking | `/api/firewall/block-country` |
| **Traffic** | Network Analysis | `/api/firewall/traffic/analysis` |

---

## 🔒 Blocking Commands

### Block IP
```powershell
$body = @{ ip = "198.51.100.50"; reason = "Malicious activity" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/block-ip" `
    -Method Post -Body $body -ContentType "application/json"
```

### Block Domain
```powershell
$body = @{ domain = "malicious-site.com"; reason = "Phishing" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/block-domain" `
    -Method Post -Body $body -ContentType "application/json"
```

### Block Application
```powershell
$body = '{"application":"torrent"}' 
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/block-application" `
    -Method Post -Body $body -ContentType "application/json"
```

### Block Country
```powershell
$body = '{"countryCode":"KP"}'
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/block-country" `
    -Method Post -Body $body -ContentType "application/json"
```

---

## 📊 Monitoring Commands

### Get Statistics
```powershell
$stats = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/statistics"
Write-Host "Packets: $($stats.statistics.packetsInspected)"
Write-Host "Blocked: $($stats.statistics.threatsBlocked)"
Write-Host "Allowed: $($stats.statistics.allowedConnections)"
```

### Get DPI Detections
```powershell
$dpi = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/dpi/detections?limit=10"
foreach ($d in $dpi.detections) {
    Write-Host "[$($d.severity)] $($d.name) from $($d.sourceIP)"
}
```

### Get IDS Alerts
```powershell
$ids = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/ids/alerts?limit=10"
foreach ($a in $ids.alerts) {
    Write-Host "[$($a.severity)] $($a.type) - $($a.sourceIP)"
}
```

### Get Traffic Analysis
```powershell
$traffic = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/traffic/analysis"
Write-Host "Bandwidth: $([math]::Round($traffic.bandwidth.total / 1MB, 2)) MB"
Write-Host "Anomalies: $($traffic.anomalies.Count)"
```

---

## ⚙️ Rule Management

### Get All Rules
```powershell
$rules = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/rules"
foreach ($r in $rules.rules) {
    Write-Host "[$($r.priority)] $($r.name) - $($r.action)"
}
```

### Add Custom Rule
```powershell
$rule = @{
    name = "Block Telnet"
    type = "port"
    action = "block"
    direction = "inbound"
    protocol = "tcp"
    ports = @(23)
    enabled = $true
    priority = 2
    description = "Block insecure Telnet"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/rules" `
    -Method Post -Body $rule -ContentType "application/json"
```

### Update Rule
```powershell
$update = @{ enabled = $false } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/rules/fw_001" `
    -Method Put -Body $update -ContentType "application/json"
```

### Delete Rule
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/rules/fw_custom_123" `
    -Method Delete
```

---

## 🎯 Detection Signatures

### DPI Categories
- **Malware**: PE headers, code injection, obfuscation
- **Exploits**: Path traversal, XSS, SQL injection
- **DDoS**: LOIC, HOIC, Slowloris
- **Crypto Miners**: Stratum protocol, browser miners
- **C2 Communication**: Remote commands, beacons

### IDS Signatures
- **port_scan**: 10+ connections in 60s
- **brute_force_ssh**: 5+ attempts in 5min
- **brute_force_rdp**: 3+ attempts in 10min
- **syn_flood**: 100+ packets in 10s
- **udp_flood**: 200+ packets in 10s
- **icmp_flood**: 50+ packets in 10s

### Application Signatures
- **torrent**: BitTorrent, uTorrent (ports 6881-6889)
- **p2p**: eMule, KaZaA (ports 4662, 4672)
- **remote_desktop**: RDP (port 3389)
- **ssh**: OpenSSH, PuTTY (port 22)
- **vpn**: OpenVPN, IPSec (ports 1194, 500, 4500)

---

## 🔍 Quick Diagnostics

### Check Current Blocks
```powershell
$blocked = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/blocked"
Write-Host "Blocked IPs: $($blocked.ips.Count)"
Write-Host "Blocked Apps: $($blocked.applications.Count)"
Write-Host "Blocked Countries: $($blocked.countries.Count)"
```

### View Recent Threats
```powershell
$dpi = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/dpi/detections?limit=5"
$ids = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/ids/alerts?limit=5"
$ips = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/ips/blocks?limit=5"

Write-Host "DPI: $($dpi.count) | IDS: $($ids.count) | IPS: $($ips.count)"
```

---

## 🎮 Control Commands

### Start/Stop Monitoring
```powershell
# Start
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/monitoring/start" -Method Post

# Stop
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/monitoring/stop" -Method Post
```

### Reset Statistics
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/statistics/reset" -Method Post
```

---

## 💡 Common Use Cases

### Block All Tor Traffic
```powershell
# Tor exit nodes are automatically blocked by default rule fw_002
$rules = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/rules"
$torRule = $rules.rules | Where-Object { $_.name -eq "Block Tor Exit Nodes" }
Write-Host "Tor blocking: $($torRule.enabled)"
```

### Prevent Cryptocurrency Mining
```powershell
# Enabled by default rule fw_003
$rules = Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/rules"
$minerRule = $rules.rules | Where-Object { $_.name -like "*Cryptocurrency*" }
Write-Host "Mining blocked: $($minerRule.enabled)"
```

### Geographic Restrictions
```powershell
# Block high-risk countries
@('KP', 'IR', 'SY') | ForEach-Object {
    $body = @{ countryCode = $_ } | ConvertTo-Json
    Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/block-country" `
        -Method Post -Body $body -ContentType "application/json"
}
```

### Application Control
```powershell
# Block P2P applications
@('torrent', 'p2p') | ForEach-Object {
    $body = @{ application = $_ } | ConvertTo-Json
    Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/block-application" `
        -Method Post -Body $body -ContentType "application/json"
}
```

---

## 📈 Performance Metrics

| Component | CPU Impact | Memory | Latency |
|-----------|------------|--------|---------|
| DPI | 5-15% | 50-100MB | 2-5% |
| IDS | 3-8% | 30-60MB | 1-3% |
| IPS | 2-5% | 20-40MB | 1-2% |
| App Filter | 1-3% | 10-20MB | <1% |
| Geo-Blocker | 1-2% | 5-10MB | <1% |
| Traffic Analyzer | 2-5% | 20-40MB | <1% |

**Total:** 14-38% CPU, 135-270MB RAM, 5-12% latency

---

## 🚨 Troubleshooting

### High False Positives
```powershell
# Add IP to allowlist
$body = @{ ip = "192.168.1.100" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/unblock-ip" `
    -Method Post -Body $body -ContentType "application/json"
```

### Reset Everything
```powershell
# Stop monitoring
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/monitoring/stop" -Method Post

# Reset statistics
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/statistics/reset" -Method Post

# Restart monitoring
Invoke-RestMethod -Uri "http://localhost:8080/api/firewall/monitoring/start" -Method Post
```

---

## 📚 Documentation

- **Full Guide**: `ADVANCED_FIREWALL_GUIDE.md`
- **API Reference**: See full guide for complete endpoint documentation
- **Code**: `backend/advanced-firewall.js`

---

**Quick Reference v1.0 - Advanced Firewall 🛡️**
