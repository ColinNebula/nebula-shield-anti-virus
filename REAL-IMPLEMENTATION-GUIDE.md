# Nebula Shield - Real Implementation Guide

## ✅ Implemented Features

### 1. Real System Monitoring
- **CPU**: Actual usage, cores, model, temperature (systeminformation)
- **Memory**: Real RAM tracking with total/used/free
- **Disk**: All drives detected with actual space calculations
- **Processes**: Real running processes with PIDs, CPU%, memory
- **Network**: Real IP addresses and MAC addresses

### 2. Real File Scanning
- **Quick Scan**: Temp folders, Downloads, AppData
- **Full Scan**: Entire C:\ drive (limited to 10k files for performance)
- **Hashing**: MD5 and SHA256 file hashing
- **Detection**: Pattern-based suspicious file detection
- **VirusTotal**: Optional integration for real malware detection

### 3. Quarantine System
- **Location**: `%APPDATA%\nebula-shield-anti-virus\quarantine`
- **Encryption**: XOR encryption for file isolation
- **Database**: JSON file tracking all quarantined files
- **Operations**: Quarantine, Restore, Permanent Delete
- **Metadata**: Original path, hash, threat info, timestamps

### 4. Disk Cleanup
- **Categories**:
  - Temporary Files (System & User Temp)
  - Browser Cache (Chrome, Edge, Firefox)
  - Windows Update Cache
  - Recycle Bin
  - Old Downloads (30+ days)
- **Analysis**: Scans and calculates reclaimable space
- **Cleanup**: Category-specific or full cleanup

### 5. VirusTotal Integration
- **API**: VirusTotal v3 REST API
- **Database**: 75+ million signatures across 70+ engines
- **Features**: File hash scanning, real threat names
- **Rate Limit**: 4 requests/minute (free tier)
- **Setup**: Requires free API key

## 🚀 Setup Instructions

### Basic Setup (No VirusTotal)
The system works without VirusTotal using pattern-based detection:

```bash
cd backend
npm install
npm start
```

### Advanced Setup (With VirusTotal)

1. **Get Free API Key**
   - Visit: https://www.virustotal.com/gui/join-us
   - Sign up for free account
   - Go to: https://www.virustotal.com/gui/user/[username]/apikey
   - Copy your API key

2. **Set Environment Variable**

   **Windows PowerShell**:
   ```powershell
   $env:VIRUSTOTAL_API_KEY="your_api_key_here"
   ```

   **Windows CMD**:
   ```cmd
   set VIRUSTOTAL_API_KEY=your_api_key_here
   ```

   **Permanent (Windows)**:
   ```powershell
   [System.Environment]::SetEnvironmentVariable('VIRUSTOTAL_API_KEY', 'your_key', 'User')
   ```

3. **Restart Backend**
   ```bash
   cd backend
   npm start
   ```

4. **Verify**
   ```powershell
   curl http://localhost:8080/api/virustotal/stats
   ```
   Should show: `"configured": true`

## 📡 API Endpoints

### System Monitoring
```
GET  /api/system/health      - Real CPU, memory, disk, processes
GET  /api/status             - Protection status
```

### File Scanning
```
POST /api/scan/quick         - Quick scan (Temp, Downloads)
POST /api/scan/full          - Full system scan
GET  /api/scan/status        - Current scan progress
GET  /api/scan/results       - Get scan results
GET  /api/scan/history       - Scan history
```

### Quarantine
```
GET    /api/quarantine           - List quarantined files
POST   /api/quarantine           - Quarantine a file
POST   /api/quarantine/:id/restore - Restore file
DELETE /api/quarantine/:id       - Permanently delete
GET    /api/quarantine/stats     - Quarantine statistics
```

### Disk Cleanup
```
GET  /api/disk/analyze       - Analyze disk space
GET  /api/disk/results       - Get cleanup results
POST /api/disk/clean/:category - Clean specific category
POST /api/disk/clean/all     - Clean all categories
```

Categories: `tempFiles`, `browserCache`, `windowsUpdate`, `recycleBin`, `downloads`

### VirusTotal
```
POST /api/virustotal/scan    - Scan file path
POST /api/virustotal/hash    - Scan file hash
GET  /api/virustotal/stats   - Service statistics
```

### Signatures
```
POST /api/signatures/update  - Update virus signatures
```

## 🔧 Configuration

### Enable VirusTotal in File Scanner

Edit `backend/real-file-scanner.js`:
```javascript
this.useVirusTotal = true; // Change to true
```

This makes the scanner automatically check suspicious files with VirusTotal.

### Performance Tuning

**Quick Scan Limits** (in `real-file-scanner.js`):
```javascript
maxFiles = 1000;  // Increase for more thorough scanning
```

**Full Scan Limits**:
```javascript
maxFiles = 10000; // Increase (may slow down scans)
```

**Disk Cleanup Limits** (in `disk-cleanup-manager.js`):
```javascript
files.slice(0, 500) // Increase to scan more files
```

## 📱 Mobile App Integration

Your mobile app already uses these endpoints via `ApiService.ts`:
- Dashboard shows real CPU, memory, disk from `/api/system/health`
- Scans trigger real file scanning via `/api/scan/*`
- Settings update uses real signature counts

## 🔒 Security Notes

1. **Quarantine Encryption**: Files are XOR encrypted - sufficient for isolation but not cryptographically secure
2. **File Permissions**: Some system files require admin privileges
3. **VirusTotal**: Free tier limited to 4 requests/minute
4. **Disk Cleanup**: Always review files before permanent deletion

## 🐛 Troubleshooting

### VirusTotal Not Working
```powershell
# Check if API key is set
echo $env:VIRUSTOTAL_API_KEY

# Test API key
curl -H "x-apikey: your_key" https://www.virustotal.com/api/v3/users/current
```

### Quarantine Permission Errors
Run backend with elevated privileges or ensure write access to `%APPDATA%`

### Scan Not Finding Files
- Check file permissions
- Review `ignore` patterns in `real-file-scanner.js`
- Verify paths exist and are accessible

## 📊 Modules Created

| Module | File | Purpose |
|--------|------|---------|
| System Monitor | `real-system-monitor.js` | CPU, memory, disk, processes |
| File Scanner | `real-file-scanner.js` | Real filesystem scanning |
| Quarantine | `quarantine-manager.js` | File isolation and management |
| Disk Cleanup | `disk-cleanup-manager.js` | Junk file removal |
| VirusTotal | `virustotal-service.js` | Malware detection API |

## 🎯 Next Steps

1. **Get VirusTotal API Key** for real malware detection
2. **Test Quarantine** with a safe test file
3. **Run Disk Cleanup** to free up space
4. **Monitor Performance** on mobile app

All simulated features are now **fully functional** with real system integration!
