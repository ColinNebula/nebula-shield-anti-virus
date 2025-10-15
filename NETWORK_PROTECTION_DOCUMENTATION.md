# Network Protection Feature

## Overview
Comprehensive network security suite providing real-time monitoring, threat detection, firewall management, and intrusion prevention.

## 🔍 Key Features

### 1. Real-Time Network Monitor
- **Active Connections**: View all current network connections
- **Process Tracking**: Identify which applications are using the network
- **Bandwidth Monitoring**: Track data sent/received per connection
- **GeoIP Mapping**: See where connections are going (country, city, organization)
- **Connection States**: ESTABLISHED, LISTENING, SYN_RECEIVED, etc.

### 2. Threat Detection Engine
**Malicious IP Database**:
- 6 known malicious IPs (expandable)
- Command & Control (C2) server detection
- Tor exit node identification

**Suspicious Activity Detection**:
- Backdoor ports (4444, 5555, 6666, 31337, etc.)
- Common exploit ports (RDP 3389, SMB 445, Telnet 23)
- Unsolicited inbound connections
- Anonymous proxy usage (Tor)

**Threat Levels**:
- 🔴 **Critical**: Immediate action required (e.g., C2 server, RDP brute force)
- 🟠 **High**: Strongly recommended to block (e.g., Tor exit nodes)
- 🟡 **Medium**: Investigate further (e.g., suspicious ports)

### 3. Port Scanner
Scans your system for open ports and assesses security risks:

**Risk Assessment**:
- **High Risk**: RDP (3389), SMB (445) - frequent attack targets
- **Medium Risk**: RPC (135), VNC (5900) - potential vulnerabilities
- **Low Risk**: HTTP (80), HTTPS (443), Dev servers (3000, 8082)

**Detected Services**:
- HTTP/HTTPS web servers
- Remote Desktop Protocol (RDP)
- Server Message Block (SMB/File sharing)
- Virtual Network Computing (VNC)
- Node.js development servers
- Windows RPC services

### 4. Firewall Management

**Pre-configured Rules**:
1. **Block Tor Network** - Prevents anonymization attempts
2. **Block Inbound RDP** - Prevents remote access attacks
3. **Allow Web Browsing** - HTTP/HTTPS traffic
4. **Block SMB** - Prevents ransomware spread

**Custom Rules**:
- Direction: Inbound, Outbound, or Both
- Action: Allow or Block
- Protocol: TCP, UDP, ICMP
- Port filtering: Single ports or ranges
- IP filtering: Specific IPs or wildcards
- Priority system for rule ordering

**One-Click IP Blocking**:
- Block suspicious connections instantly
- Automatic rule creation
- Custom reason/description

### 5. Security Profiles

**🛡️ Maximum Security**
- **Use Case**: Public Wi-Fi, high-risk environments
- **Rules**:
  - Block ALL inbound connections
  - Allow only HTTP/HTTPS outbound
  - Disable file sharing
  - Maximum protection, reduced functionality

**⚖️ Balanced (Recommended)**
- **Use Case**: Daily home/office use
- **Rules**:
  - Block common exploit ports (SMB, RDP, Telnet)
  - Allow standard services (web, email, FTP)
  - Moderate protection with good usability

**🎮 Gaming**
- **Use Case**: Online gaming, streaming
- **Rules**:
  - Open Xbox/PlayStation ports (3074, 3075)
  - Open Steam ports (27015, 27036)
  - Allow all outbound traffic
  - Minimal restrictions for best performance

## 📊 Dashboard Statistics

### Summary Cards
1. **Active Connections**: Number of established connections
2. **Threats Detected**: Critical/High/Medium threats found
3. **Packets Blocked**: Total blocked by firewall
4. **Bandwidth Usage**: Current Mbps usage

### Network Statistics
- **Total Traffic**: Cumulative sent/received data
- **Packet Blocking**: Real-time firewall activity
- **Bandwidth Trends**: Current, peak, and average speeds
- **Top Processes**: Applications using most bandwidth

## 🌍 GeoIP Database

**Supported Organizations**:
- 🇺🇸 Google LLC (8.8.8.8, 142.250.x.x, 172.217.x.x)
- 🇺🇸 Cloudflare (1.1.1.1)
- 🇺🇸 Microsoft (13.107.x.x, 20.190.x.x)
- 🇺🇸 Twitter (104.244.x.x)
- 🇺🇸 Fastly CDN (151.101.x.x)
- ⚠️ Tor Exit Nodes (185.220.x.x)
- 🇷🇺 Unknown ISPs (91.219.x.x)
- 🏠 Local Network (192.168.x.x, 10.x.x.x, 172.x.x.x)

## 🚨 Sample Threats

The system will detect and alert on:

1. **Tor Exit Node Connection**
   - IP: 185.220.101.1:9001
   - Process: unknown.exe
   - Threat Level: HIGH
   - Description: "Connection to known Tor exit node - possible anonymization attempt"

2. **Suspicious Inbound RDP**
   - IP: 91.219.236.197 (Russia)
   - Port: 3389 (RDP)
   - Threat Level: CRITICAL
   - Description: "Unsolicited RDP connection attempt from suspicious IP"

3. **Open SMB Port**
   - Port: 445
   - Risk: HIGH
   - Recommendation: "File sharing - disable if not needed, frequently targeted by ransomware"

## 🛠️ How to Use

### Monitoring Active Connections
1. Navigate to **Network Protection** → **Active Connections** tab
2. Review all active connections in real-time
3. Check for red-highlighted threats
4. View geographic location and bandwidth usage
5. Click "Block" button to immediately block suspicious IPs

### Scanning for Open Ports
1. Go to **Open Ports** tab
2. Click **"Scan Ports"** button
3. Review discovered ports and risk levels
4. Follow security recommendations
5. Consider closing high-risk ports if not needed

### Managing Firewall Rules
1. Navigate to **Firewall Rules** tab
2. Toggle rules on/off with switches
3. Click **"Add Rule"** to create custom rules
4. Delete unwanted rules with trash icon
5. Rules are applied immediately

### Creating Custom Rules
1. Click **"Add Rule"** button
2. Enter rule name (e.g., "Block Port 23")
3. Select direction: Inbound/Outbound/Both
4. Choose action: Allow or Block
5. Select protocol: TCP/UDP/ICMP
6. Enter ports (comma-separated) or leave empty for all
7. Add description
8. Click **"Add Rule"**

### Applying Security Profiles
1. Go to **Security Profiles** tab
2. Read profile descriptions
3. Click **"Apply Profile"** on desired preset
4. Confirm action
5. All firewall rules will be replaced

### Blocking an IP
1. From **Active Connections**, click block icon on threat
2. OR click **"Block IP"** button manually
3. Enter IP address
4. Provide reason (auto-filled for detected threats)
5. Click **"Block IP"**
6. Rule is created and activated immediately

## 📱 User Interface

### Tabs
- **Active Connections**: Real-time connection monitor with threat badges
- **Open Ports**: Port scanner results with risk assessment
- **Firewall Rules**: Manage all firewall rules
- **Security Profiles**: Quick-apply security presets

### Color Coding
- 🔴 **Red**: Critical threats, blocked connections
- 🟠 **Orange**: High risk, warnings
- 🟡 **Yellow**: Medium risk, caution
- 🟢 **Green**: Safe, allowed, up-to-date
- 🔵 **Blue**: Informational, neutral

### Icons
- 🛡️ Shield: Network protection, security
- ⚡ Speed: Bandwidth usage
- 🌍 Globe: Geographic location
- 🚫 Block: Blocked/blocking action
- ✅ Check: Allowed/safe connection
- ⚠️ Warning: Suspicious activity
- 🔴 Error: Critical threat

## 🔒 Security Best Practices

### General Recommendations
1. ✅ Use **Balanced** profile for daily use
2. ✅ Switch to **Maximum Security** on public Wi-Fi
3. ✅ Regularly scan for open ports
4. ✅ Close unused high-risk ports (RDP, SMB)
5. ✅ Monitor active connections periodically
6. ✅ Block suspicious IPs immediately
7. ✅ Keep firewall rules updated

### High-Risk Ports to Consider Closing
- **Port 445 (SMB)**: Ransomware propagation vector
- **Port 3389 (RDP)**: Brute force attack target
- **Port 23 (Telnet)**: Unencrypted, easily exploited
- **Port 135 (RPC)**: Windows vulnerability target
- **Port 5900 (VNC)**: Remote access exploit risk

### When to Block an IP
- ❌ Connection to known malicious IP
- ❌ Tor exit node (unless intentionally using Tor)
- ❌ Unsolicited inbound connection attempts
- ❌ Repeated connection failures (possible scanning)
- ❌ Geographic anomalies (unexpected countries)
- ❌ Unknown processes connecting to suspicious ports

## 🔧 Technical Details

### Data Refresh
- **Auto-refresh**: Every 10 seconds
- **Manual refresh**: Click "Refresh" button
- **Real-time updates**: Threats appear immediately

### Connection States
- **ESTABLISHED**: Active two-way connection
- **LISTENING**: Waiting for incoming connections
- **SYN_RECEIVED**: Connection being established
- **TIME_WAIT**: Connection closing
- **CLOSED**: No connection

### Bandwidth Calculation
- Tracked per connection
- ↑ Upload (sent bytes)
- ↓ Download (received bytes)
- Formatted as B, KB, MB, GB

## 🚀 Future Enhancements

### Planned Features
- [ ] Packet capture and analysis
- [ ] Deep packet inspection (DPI)
- [ ] VPN integration and monitoring
- [ ] DNS leak testing
- [ ] Network speed testing
- [ ] Traffic shaping/QoS
- [ ] Application-level firewall
- [ ] Intrusion Prevention System (IPS)
- [ ] Network vulnerability scanner
- [ ] Automated threat response
- [ ] Connection history/logging
- [ ] Export firewall rules
- [ ] Import rules from file
- [ ] Scheduled port scans

### Database Improvements
- [ ] Expand malicious IP database (integrate with threat feeds)
- [ ] Real-time threat intelligence API
- [ ] Machine learning for anomaly detection
- [ ] Behavioral analysis
- [ ] Reputation scoring for IPs

## 📝 API Reference

### `getActiveConnections()`
Returns all active network connections with threat analysis.

**Response**:
```javascript
{
  success: true,
  connections: [
    {
      id: 'conn_001',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 54321,
      remoteAddress: '142.250.185.46',
      remotePort: 443,
      state: 'ESTABLISHED',
      process: 'chrome.exe',
      pid: 8432,
      direction: 'outbound',
      bandwidth: { sent: 12400, received: 45600 },
      duration: 127,
      geo: {
        country: 'United States',
        city: 'Mountain View',
        org: 'Google LLC',
        flag: '🇺🇸'
      },
      threat: null // or { level: 'critical', type: '...', description: '...' }
    }
  ],
  summary: {
    total: 9,
    established: 6,
    listening: 3,
    threats: 2,
    inbound: 3,
    outbound: 6
  }
}
```

### `scanOpenPorts()`
Scans local machine for open ports.

**Response**:
```javascript
{
  success: true,
  ports: [
    {
      port: 445,
      service: 'SMB',
      state: 'LISTENING',
      process: 'System',
      risk: 'high',
      recommendation: 'File sharing - disable if not needed...'
    }
  ],
  summary: {
    total: 8,
    low: 4,
    medium: 2,
    high: 2
  }
}
```

### `getFirewallRules()`
Returns all configured firewall rules.

### `blockIP(ip, reason)`
Creates rule to block specific IP address.

### `applySecurityProfile(profileName)`
Applies preset security configuration ('maximum', 'balanced', 'gaming').

## 🆘 Troubleshooting

### No Connections Showing
- Check if services are running (React app, auth server)
- Click "Refresh" button
- Verify browser has network access

### Port Scan Not Working
- May require administrator privileges (not simulated)
- Try clicking "Scan Ports" again
- Check browser console for errors

### Firewall Rules Not Saving
- Refresh the page
- Check browser console for errors
- Rules are stored in memory (reset on refresh)

## 🔗 Related Features
- **Web Protection**: URL/phishing scanning
- **Email Protection**: Spam/phishing detection
- **Driver Scanner**: Outdated driver detection
- **System Scanner**: Malware detection

---

**Note**: This is a demonstration/monitoring tool. For production use, integrate with actual system APIs (netstat, Windows Firewall, iptables, etc.).
