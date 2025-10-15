# 🛡️ Nebula Shield - Threat Handling System Guide

## 📋 Overview

Nebula Shield uses a comprehensive **multi-layered threat handling system** that detects, quarantines, cleans, and manages malicious files. This guide explains how threats are handled from detection to resolution.

---

## 🎯 Threat Handling Flow

```
┌─────────────────────┐
│  File Detected      │
│  (Scan/Monitor)     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Signature Check    │
│  Heuristic Analysis │
│  Threat Score       │
└──────────┬──────────┘
           │
           ├─── Clean ──────────> Allow File
           │
           ├─── Suspicious ─────> User Warning
           │
           └─── Infected ───┐
                           │
                           ▼
           ┌───────────────────────────┐
           │   Threat Actions          │
           ├───────────────────────────┤
           │ 1. Quarantine (Default)   │
           │ 2. Clean/Repair           │
           │ 3. Delete Permanently     │
           │ 4. Ignore (User Choice)   │
           └───────────────────────────┘
                           │
                           ▼
           ┌───────────────────────────┐
           │   Quarantine System       │
           ├───────────────────────────┤
           │ • Encrypt File            │
           │ • Store Metadata (SQLite) │
           │ • Delete Original         │
           │ • Allow Restore/Delete    │
           └───────────────────────────┘
```

---

## 🔍 Detection Methods

### 1. **Signature-Based Detection**
```cpp
// Backend: threat_detector.cpp
bool hasVirusSignature(const std::vector<uint8_t>& file_data) {
    // Compares file bytes against known virus signatures
    // 50+ virus signatures loaded from database
    // Returns true if match found
}
```

**How it works:**
- Loads 50+ virus signatures from SQLite database
- Scans file byte-by-byte for pattern matches
- Fast and reliable for known threats
- Located in: `backend/src/threat_detector.cpp`

### 2. **Heuristic Analysis**
```cpp
double calculateThreatScore(const std::string& file_path, 
                          const std::vector<uint8_t>& file_data) {
    // Analyzes file characteristics:
    // - Suspicious API calls
    // - Encryption patterns
    // - Code obfuscation
    // - Packing detection
    // Returns score: 0.0 (safe) to 1.0 (malicious)
}
```

**Score Interpretation:**
- `0.0 - 0.3`: Clean
- `0.3 - 0.7`: Suspicious (user warning)
- `0.7 - 1.0`: Malicious (quarantine)

### 3. **Behavioral Analysis** (Advanced)
```cpp
bool analyzeProcessBehavior(const std::string& process_name);
bool detectNetworkAnomalies();
bool analyzeRegistryChanges();  // Windows only
```

---

## 🗂️ Quarantine System

### **Architecture**

#### **Backend (C++)**
- **Location:** `backend/src/threat_detector.cpp`
- **Quarantine Directory:** `backend/quarantine/`
- **File Format:** `filename.quarantined`
- **Size Limit:** 1 GB (configurable)
- **Auto-cleanup:** When limit exceeded

#### **Node.js Service**
- **Location:** `backend/quarantine-service.js`
- **Database:** `backend/data/quarantine.db` (SQLite)
- **Encryption:** AES-256-CBC
- **File Format:** `[timestamp]_[random].quar`

---

## 🔐 Quarantine Process

### **Step 1: Detection**
```javascript
// When threat is detected during scan
const threatDetected = {
  filePath: 'C:\\Users\\User\\Downloads\\malware.exe',
  threatInfo: {
    threatType: 'MALWARE',
    threatName: 'Generic.Trojan.Agent',
    riskLevel: 'high',
    detectedBy: 'Real-Time Scanner',
    confidence: 0.95
  }
};
```

### **Step 2: Quarantine File**
```javascript
// Frontend API call
await AntivirusAPI.quarantineFile(filePath, threatInfo);

// Backend processing:
// 1. Calculate file hash (SHA-256)
// 2. Check if already quarantined
// 3. Read file content
// 4. Encrypt with AES-256-CBC
// 5. Generate unique filename: [timestamp]_[random].quar
// 6. Save to quarantine vault
// 7. Store metadata in SQLite
// 8. Delete original file
```

### **Step 3: Store Metadata**
```sql
-- SQLite Database Schema
CREATE TABLE quarantine (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_name TEXT NOT NULL,
  original_path TEXT NOT NULL,
  quarantine_path TEXT NOT NULL,
  threat_type TEXT NOT NULL,      -- VIRUS, MALWARE, TROJAN, etc.
  threat_name TEXT NOT NULL,      -- Specific threat identifier
  file_size INTEGER NOT NULL,
  file_hash TEXT NOT NULL,        -- SHA-256 hash
  risk_level TEXT NOT NULL,       -- high, medium, low
  quarantined_date INTEGER NOT NULL,
  encrypted INTEGER DEFAULT 1,
  metadata TEXT                   -- JSON with additional info
);
```

---

## 🔧 Threat Actions

### **1. Quarantine (Recommended)**
```javascript
// Quarantine a detected threat
const result = await AntivirusAPI.quarantineFile(filePath, {
  threatType: 'VIRUS',
  threatName: 'Win32.TrojanDownloader',
  riskLevel: 'high'
});

// Response:
{
  success: true,
  quarantineId: 5,
  quarantinePath: 'backend/quarantine_vault/1699564321_a1b2c3d4.quar',
  encrypted: true
}
```

**What happens:**
- ✅ File encrypted with AES-256
- ✅ Original file deleted
- ✅ Metadata stored in database
- ✅ User can restore or permanently delete later
- ✅ Safe and reversible

### **2. Clean/Repair**
```cpp
// Backend: threat_detector.cpp
bool cleanFile(const std::string& file_path) {
    // 1. Create backup
    // 2. Scan for virus signatures
    // 3. Remove/nullify malicious bytes
    // 4. Verify file integrity
    // 5. Keep backup for safety
}
```

**Use cases:**
- Document macros infected
- Script files with embedded malware
- Files where infection is isolated
- User wants to keep the file

**Limitations:**
- Not all threats can be cleaned
- Some files may become corrupted
- Only removes known signatures

### **3. Delete Permanently**
```javascript
// Frontend: Delete without quarantine
await AntivirusAPI.deleteQuarantinedFile(fileId);

// Or bulk delete
await AntivirusAPI.bulkDeleteQuarantined([id1, id2, id3]);
```

**When to use:**
- High-risk threats
- Confirmed malware with no value
- User decision after quarantine
- **Warning:** Cannot be undone!

### **4. Ignore (User Choice)**
```javascript
// User can choose to ignore warning and allow file
// Used for false positives or trusted files
// File added to whitelist/exclusions
```

---

## 📊 Quarantine Management

### **View Quarantined Files**
```javascript
// Frontend: Quarantine.js component
const files = await AntivirusAPI.getQuarantinedFiles();

// Returns array:
[
  {
    id: 1,
    fileName: 'malware.exe',
    originalPath: 'C:\\Downloads\\malware.exe',
    threatType: 'VIRUS',
    threatName: 'Win32.Trojan',
    riskLevel: 'high',
    fileSize: 1024000,
    quarantineDate: '2025-10-13T10:30:00Z',
    encrypted: true
  },
  // ... more files
]
```

### **Restore from Quarantine**
```javascript
// Restore single file
await AntivirusAPI.restoreFromQuarantine(fileId, targetPath);

// Bulk restore
await AntivirusAPI.bulkRestoreQuarantined([id1, id2, id3]);

// Backend process:
// 1. Decrypt file content
// 2. Restore to original or specified path
// 3. Remove from quarantine database
// 4. Delete encrypted file
```

**⚠️ Restore Warnings:**
- File still contains threat
- Real-time protection may re-quarantine
- Only restore if false positive confirmed
- Consider scanning again after restore

### **Delete from Quarantine**
```javascript
// Permanently delete encrypted file
await AntivirusAPI.deleteQuarantinedFile(fileId);

// Backend:
// 1. Delete encrypted .quar file
// 2. Remove database entry
// 3. Free up disk space
```

### **Get Statistics**
```javascript
const stats = await AntivirusAPI.getQuarantineStats();

// Returns:
{
  totalFiles: 15,
  totalSize: 45678912,  // bytes
  byThreatType: {
    'MALWARE': 8,
    'VIRUS': 5,
    'ADWARE': 2
  },
  byRiskLevel: {
    'high': 10,
    'medium': 3,
    'low': 2
  }
}
```

---

## 🎛️ Configuration Options

### **Auto-Quarantine**
```javascript
// Settings configuration
{
  autoQuarantine: true,  // Automatically quarantine detected threats
  quarantineHighRiskOnly: false,  // Only auto-quarantine high risk
  promptBeforeQuarantine: false   // Ask user before quarantine
}
```

### **Quarantine Limits**
```cpp
// C++ Backend: threat_detector.cpp
max_quarantine_size_ = 1024 * 1024 * 1024;  // 1 GB

// Auto-cleanup when exceeded:
// - Deletes oldest files first
// - Keeps high-risk threats longer
// - Logs cleanup actions
```

### **Retention Policy**
```javascript
// Node.js Service: quarantine-service.js
// Clean up files older than 30 days
await quarantineService.cleanupOldFiles(30);

// Configurable:
// - 7 days: Aggressive cleanup
// - 30 days: Default
// - 90 days: Long-term retention
// - Never: Manual cleanup only
```

---

## 🚨 Real-Time Protection

### **How Real-Time Scanning Works**
```cpp
// File Monitor: file_monitor.cpp
// Monitors directories for file changes:
// - C:\Users\[User]\Downloads
// - C:\Users\[User]\Documents
// - C:\Windows\Temp
// - Startup folders
// - Program Files

// When file created/modified:
1. Scan file immediately
2. If threat detected:
   - Block file access
   - Quarantine automatically
   - Notify user
3. If clean: Allow access
```

### **User Notifications**
```javascript
// Frontend: Toast notifications
toast.error('⚠️ Threat detected and quarantined: malware.exe');
toast.warning('🔍 Suspicious file detected: document.doc');
toast.success('✅ File cleaned successfully: script.vbs');
```

---

## 📡 API Endpoints

### **Quarantine a File**
```http
POST /api/quarantine/add
Content-Type: application/json

{
  "filePath": "C:\\path\\to\\suspicious.exe",
  "threatInfo": {
    "threatType": "VIRUS",
    "threatName": "Win32.TrojanDownloader",
    "riskLevel": "high",
    "detectedBy": "Email Scanner"
  }
}
```

### **Get All Quarantined Files**
```http
GET /api/quarantine
```

### **Restore File**
```http
POST /api/quarantine/:id/restore
Content-Type: application/json

{
  "targetPath": "C:\\RestoreHere\\file.exe"  // Optional
}
```

### **Delete File**
```http
DELETE /api/quarantine/:id
```

### **Bulk Operations**
```http
POST /api/quarantine/bulk/delete
Content-Type: application/json

{
  "ids": [1, 2, 3]
}
```

### **Get Statistics**
```http
GET /api/quarantine/stats
```

---

## 🔬 Testing Threat Handling

### **Test 1: Create EICAR Test File**
```bash
# EICAR is a standard test file for antivirus software
# NOT a real virus, safe to use
echo X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* > eicar.txt
```

### **Test 2: Scan EICAR File**
```javascript
const result = await AntivirusAPI.scanFile('C:\\path\\to\\eicar.txt');

// Expected result:
{
  infected: true,
  threatType: 'TEST',
  threatName: 'EICAR-Test-File',
  riskLevel: 'low',
  confidence: 1.0
}
```

### **Test 3: Auto-Quarantine**
```javascript
// With auto-quarantine enabled:
// 1. Real-time monitor detects EICAR
// 2. Automatically quarantines
// 3. User receives notification
// 4. File appears in quarantine list
```

### **Test 4: Restore and Re-Scan**
```javascript
// 1. Restore EICAR from quarantine
await AntivirusAPI.restoreFromQuarantine(fileId);

// 2. Re-scan
const result = await AntivirusAPI.scanFile(restoredPath);

// 3. Should detect again (if real-time protection enabled)
```

---

## 📂 File Locations

### **Backend (C++)**
```
backend/
├── quarantine/                   # C++ quarantine directory
│   └── *.quarantined            # Quarantined files
├── include/threat_detector.h    # Threat detection header
├── src/threat_detector.cpp      # Detection & quarantine logic
├── src/file_monitor.cpp         # Real-time monitoring
└── data/
    └── virus_signatures.db      # Signature database (50+)
```

### **Node.js Service**
```
backend/
├── quarantine-service.js        # Main quarantine service
├── quarantine_vault/            # Encrypted files storage
│   └── *.quar                   # Encrypted quarantine files
└── data/
    └── quarantine.db            # SQLite metadata
```

### **Frontend**
```
src/
├── components/
│   └── Quarantine.js            # Quarantine management UI
├── services/
│   ├── antivirusApi.js          # API client
│   └── enhancedScanner.js       # Frontend scanner logic
└── pages/
    └── EnhancedScanner.js       # Scanner interface
```

---

## 🎨 User Interface

### **Quarantine Component** (`src/components/Quarantine.js`)

**Features:**
- 📋 List all quarantined files
- 🔍 Search and filter by threat type
- ✅ Bulk select files
- ♻️ Restore files (individual or bulk)
- 🗑️ Delete files (individual or bulk)
- 📊 View threat details
- 📈 Statistics dashboard
- 📄 Export reports

**Visual Elements:**
- Color-coded risk levels:
  - 🔴 Red: High risk
  - 🟡 Yellow: Medium risk
  - 🔵 Blue: Low risk
- File icons by threat type
- Timestamp formatting
- File size display
- Action buttons with confirmation

---

## 🛡️ Security Features

### **Encryption**
```javascript
// AES-256-CBC encryption for quarantined files
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);

// Key: 32-byte encryption key (configurable)
// IV: Random initialization vector per file
// Result: Unreadable encrypted file
```

### **File Hash Verification**
```javascript
// SHA-256 hash prevents duplicates
const hash = crypto.createHash('sha256')
  .update(fileContent)
  .digest('hex');

// Check if file already quarantined by hash
const existing = await findByHash(hash);
```

### **Access Control**
- Quarantine directory permissions: Admin only
- Database encryption: SQLite with encryption extension
- API authentication: Required for all operations
- Audit logging: All actions logged

---

## 📊 Monitoring & Logs

### **Quarantine Logs**
```
[2025-10-13 10:30:45] INFO: File quarantined: malware.exe -> 1699564321_a1b2c3d4.quar
[2025-10-13 10:31:10] INFO: Quarantine usage: 245 MB / 1 GB (24%)
[2025-10-13 11:00:00] INFO: Cleanup triggered: Quarantine > 80%
[2025-10-13 11:00:05] INFO: Deleted 3 old quarantine files (freed 15 MB)
[2025-10-13 14:20:30] WARN: Restore requested for high-risk file: trojan.exe
[2025-10-13 14:20:35] INFO: File restored: trojan.exe -> C:\Restored\trojan.exe
```

### **Threat Statistics**
```javascript
// Dashboard displays:
- Total threats detected: 47
- Currently quarantined: 15
- Threats cleaned: 8
- False positives: 3
- Files restored: 2
- Permanently deleted: 27
```

---

## 🚀 Best Practices

### **For Users**
1. ✅ **Enable auto-quarantine** for automatic protection
2. ⚠️ **Review quarantine regularly** (weekly)
3. 🗑️ **Delete old threats** you won't restore
4. 🔍 **Verify before restore** - scan again
5. 📊 **Check statistics** for threat trends
6. 🔄 **Keep signatures updated** for latest threats

### **For Developers**
1. 🔐 **Always encrypt** quarantined files
2. 📝 **Log all operations** for audit trail
3. 🧪 **Test with EICAR** standard test file
4. 💾 **Implement size limits** to prevent disk full
5. 🔄 **Auto-cleanup** old files
6. 🎯 **Use correct threat types** for classification
7. ⚡ **Handle errors gracefully** - restore on failure

---

## 🐛 Troubleshooting

### **Issue: File won't quarantine**
```
Possible causes:
1. Insufficient disk space
2. File in use by another process
3. Permission denied
4. Quarantine limit exceeded

Solution:
- Check disk space: >2x file size needed
- Close programs using file
- Run as administrator
- Clean up old quarantine files
```

### **Issue: Can't restore file**
```
Possible causes:
1. Target path doesn't exist
2. Permission denied
3. Decryption failed (corrupted)
4. Real-time protection re-quarantines

Solution:
- Verify target path exists
- Disable real-time protection temporarily
- Check quarantine database integrity
- Try different restore location
```

### **Issue: Database errors**
```
Error: "Database is locked"
Cause: Multiple processes accessing SQLite
Solution: Implement connection pooling or file locks

Error: "Table doesn't exist"
Cause: Database not initialized
Solution: Run quarantineService.initialize()
```

---

## 📈 Future Enhancements

### **Planned Features**
- [ ] Cloud quarantine sync
- [ ] Machine learning threat detection
- [ ] Sandboxed file execution analysis
- [ ] Automatic threat reporting
- [ ] Whitelist management
- [ ] Scheduled quarantine cleanup
- [ ] Compressed quarantine storage
- [ ] Multi-user quarantine separation

---

## ✅ Summary

**Nebula Shield Threat Handling:**

1. **Detection**: Signature + Heuristic + Behavioral analysis
2. **Action**: Quarantine (encrypted), Clean, or Delete
3. **Storage**: AES-256 encrypted files + SQLite metadata
4. **Management**: Restore, delete, bulk operations
5. **Monitoring**: Real-time protection with auto-quarantine
6. **Security**: Encryption, hashing, access control
7. **UI**: Visual quarantine manager with statistics

**Key Files:**
- Backend C++: `backend/src/threat_detector.cpp`
- Node.js Service: `backend/quarantine-service.js`
- Frontend UI: `src/components/Quarantine.js`
- API: `src/services/antivirusApi.js`

**Status:** ✅ **Fully Implemented and Operational**

---

*Last Updated: October 13, 2025*  
*Nebula Shield Anti-Virus - Complete Threat Handling System*
