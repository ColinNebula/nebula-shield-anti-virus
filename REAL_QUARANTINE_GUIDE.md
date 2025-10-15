# Real Quarantine System - Implementation Guide

## 🔒 Overview

Nebula Shield now features a **production-grade quarantine system** with actual file operations, encryption, and persistent storage. This is **NOT** a simulation - it performs real file quarantine, encryption, and restoration operations.

---

## ✅ What's Real (Not Simulated)

### 1. **Actual File Operations**
- ✅ Files are physically moved from their original location
- ✅ Original files are deleted after successful quarantine
- ✅ Files are stored in encrypted form in the quarantine vault
- ✅ Real file restoration with decryption
- ✅ Permanent deletion with secure file removal

### 2. **Encryption**
- ✅ AES-256-CBC encryption for all quarantined files
- ✅ Unique initialization vectors (IV) per file
- ✅ Encrypted files stored with `.quar` extension
- ✅ Decryption during restoration

### 3. **Database Persistence**
- ✅ SQLite database for quarantine metadata
- ✅ Survives server restarts (persistent storage)
- ✅ Stores file hash, threat info, original path, permissions
- ✅ Tracks quarantine date, threat type, risk level

### 4. **Advanced Features**
- ✅ Bulk operations (restore/delete multiple files)
- ✅ File hash tracking (prevents duplicate quarantine)
- ✅ Original file permissions preservation
- ✅ Quarantine statistics and reporting
- ✅ Automatic cleanup of old quarantine files
- ✅ Export quarantine reports (JSON format)

---

## 🏗️ Architecture

### Backend Components

#### 1. **Quarantine Service** (`backend/quarantine-service.js`)
Main service handling all quarantine operations:

```javascript
const quarantineService = require('./backend/quarantine-service');

// Quarantine a file
await quarantineService.quarantineFile(filePath, {
  threatType: 'MALWARE',
  threatName: 'Generic.Trojan',
  riskLevel: 'high',
  detectedBy: 'Real-Time Scanner'
});

// Restore a file
await quarantineService.restoreFile(fileId);

// Delete permanently
await quarantineService.deleteQuarantined(fileId);

// Get all quarantined files
const files = await quarantineService.getAllQuarantined();

// Get statistics
const stats = await quarantineService.getStatistics();
```

#### 2. **Storage Structure**
```
backend/
├── quarantine_vault/           # Encrypted files storage
│   ├── 1699564321_a1b2c3d4.quar
│   ├── 1699564322_e5f6g7h8.quar
│   └── ...
└── data/
    └── quarantine.db          # SQLite metadata database
```

#### 3. **Database Schema**
```sql
CREATE TABLE quarantine (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_name TEXT NOT NULL,
  original_path TEXT NOT NULL,
  quarantine_path TEXT NOT NULL,
  threat_type TEXT NOT NULL,
  threat_name TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  file_hash TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  quarantined_date INTEGER NOT NULL,
  encrypted INTEGER DEFAULT 1,
  metadata TEXT
);
```

---

## 🔌 API Endpoints

### Get All Quarantined Files
```http
GET /api/quarantine
```

**Response:**
```json
[
  {
    "id": 1,
    "fileName": "malware.exe",
    "originalPath": "C:\\Downloads\\malware.exe",
    "threatType": "MALWARE",
    "threatName": "Generic.Trojan",
    "fileSize": 2048576,
    "riskLevel": "high",
    "quarantinedDate": "2025-10-12T10:30:00.000Z",
    "encrypted": true
  }
]
```

### Quarantine a File
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

**Response:**
```json
{
  "success": true,
  "message": "File successfully quarantined",
  "quarantineId": 5,
  "quarantinePath": "backend/quarantine_vault/1699564321_a1b2c3d4.quar",
  "encrypted": true
}
```

### Restore File
```http
POST /api/quarantine/:id/restore
Content-Type: application/json

{
  "targetPath": "C:\\Restored\\file.exe"  // Optional
}
```

**Response:**
```json
{
  "success": true,
  "message": "File successfully restored",
  "restoredPath": "C:\\Restored\\file.exe"
}
```

### Delete File Permanently
```http
DELETE /api/quarantine/:id
```

**Response:**
```json
{
  "success": true,
  "message": "File permanently deleted from quarantine"
}
```

### Bulk Operations
```http
POST /api/quarantine/bulk/delete
POST /api/quarantine/bulk/restore

{
  "ids": [1, 2, 3]
}
```

**Response:**
```json
{
  "success": [1, 2],
  "failed": [
    {
      "id": 3,
      "error": "File not found"
    }
  ]
}
```

### Get Statistics
```http
GET /api/quarantine/stats
```

**Response:**
```json
{
  "totalFiles": 15,
  "totalSize": 45678912,
  "byThreatType": {
    "MALWARE": 8,
    "VIRUS": 5,
    "ADWARE": 2
  },
  "byRiskLevel": {
    "high": 10,
    "medium": 3,
    "low": 2
  }
}
```

### Export Report
```http
GET /api/quarantine/export
```

**Response:**
```json
{
  "generatedAt": "2025-10-12T14:30:00.000Z",
  "statistics": { /* stats object */ },
  "files": [ /* all quarantine records */ ]
}
```

---

## 🎯 Frontend Integration

### Updated Components

#### 1. **Quarantine Component** (`src/components/Quarantine.js`)
- ✅ Removed demo mode notice
- ✅ Real API calls with error handling
- ✅ Uses file ID instead of file path for operations
- ✅ Bulk operations support
- ✅ Detailed success/error messages

#### 2. **Antivirus API** (`src/services/antivirusApi.js`)
New methods added:
```javascript
// Get quarantined files
await AntivirusAPI.getQuarantinedFiles();

// Restore file
await AntivirusAPI.restoreFromQuarantine(fileId, targetPath);

// Delete file
await AntivirusAPI.deleteQuarantinedFile(fileId);

// Bulk delete
await AntivirusAPI.bulkDeleteQuarantined([1, 2, 3]);

// Bulk restore
await AntivirusAPI.bulkRestoreQuarantined([1, 2, 3]);

// Get statistics
await AntivirusAPI.getQuarantineStats();

// Export report
await AntivirusAPI.exportQuarantineReport();
```

---

## 🚀 Usage Examples

### 1. Quarantine a Detected Threat

```javascript
// In your scanner/detection code
const threatDetected = {
  filePath: 'C:\\Users\\User\\Downloads\\suspicious.exe',
  threatInfo: {
    threatType: 'MALWARE',
    threatName: 'Generic.Trojan.Agent',
    riskLevel: 'high',
    detectedBy: 'Real-Time Scanner',
    scanDate: new Date().toISOString(),
    additionalInfo: {
      scanEngine: 'Nebula Shield',
      signatures: ['Trojan.Agent.123', 'Malware.Generic.456']
    }
  }
};

// Send to backend
const response = await fetch('http://localhost:8080/api/quarantine/add', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(threatDetected)
});

const result = await response.json();
console.log(result);
// { success: true, quarantineId: 5, encrypted: true }
```

### 2. Restore a False Positive

```javascript
// User determines file was safe
const fileId = 5;

const result = await AntivirusAPI.restoreFromQuarantine(fileId);
// File is decrypted and restored to original location
toast.success(`File restored: ${result.restoredPath}`);
```

### 3. Clean Up Old Quarantine Files

```javascript
// Backend automatic cleanup (30 days default)
await quarantineService.cleanupOldFiles(30);
// Deletes files older than 30 days
```

---

## 🔐 Security Features

### 1. **Encryption**
- **Algorithm:** AES-256-CBC
- **Key Management:** Server-side encryption key (configurable via environment)
- **IV:** Unique 16-byte initialization vector per file
- **Format:** `[IV (16 bytes)][Encrypted Data]`

### 2. **File Integrity**
- **Hash Tracking:** SHA-256 hash of original file
- **Duplicate Detection:** Prevents re-quarantining same file
- **Verification:** Hash stored in database for integrity checks

### 3. **Permissions Preservation**
- Original file permissions stored in metadata
- Restored files maintain original access rights
- Graceful fallback if permission restoration fails

### 4. **Isolation**
- Quarantined files stored in isolated vault directory
- Encrypted format prevents accidental execution
- Database tracks all metadata separately

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the backend directory:

```bash
# Quarantine Configuration
QUARANTINE_ENCRYPTION_KEY=your-32-byte-hex-key-here
QUARANTINE_VAULT_PATH=/custom/path/to/vault
QUARANTINE_DB_PATH=/custom/path/to/database.db
QUARANTINE_AUTO_CLEANUP_DAYS=30
```

**Generate encryption key:**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Default Paths
- Vault: `backend/quarantine_vault/`
- Database: `backend/data/quarantine.db`

---

## 🧪 Testing

### Test Quarantine Operation

1. **Create a test file:**
```bash
echo "This is a test file" > test_malware.txt
```

2. **Quarantine via API:**
```bash
curl -X POST http://localhost:8080/api/quarantine/add \
  -H "Content-Type: application/json" \
  -d '{
    "filePath": "C:\\path\\to\\test_malware.txt",
    "threatInfo": {
      "threatType": "TEST",
      "threatName": "Test.Malware",
      "riskLevel": "low"
    }
  }'
```

3. **Verify:**
- Original file deleted: ❌ `test_malware.txt`
- Encrypted file created: ✅ `backend/quarantine_vault/[timestamp]_[random].quar`
- Database entry created: ✅ Check `quarantine.db`

4. **Restore:**
```bash
curl -X POST http://localhost:8080/api/quarantine/1/restore
```

5. **Verify restoration:**
- Encrypted file deleted: ❌ `.quar` file removed
- Original file restored: ✅ `test_malware.txt` back
- Database entry removed: ✅ Record deleted

---

## 📊 Monitoring & Reporting

### Real-Time Statistics
```javascript
const stats = await quarantineService.getStatistics();
console.log(stats);
/*
{
  totalFiles: 42,
  totalSize: 104857600, // bytes
  byThreatType: {
    MALWARE: 20,
    VIRUS: 15,
    ADWARE: 7
  },
  byRiskLevel: {
    high: 25,
    medium: 12,
    low: 5
  }
}
*/
```

### Export Reports
```javascript
const report = await quarantineService.exportReport();
// Save to file or send to admin
fs.writeFileSync('quarantine_report.json', JSON.stringify(report, null, 2));
```

---

## 🐛 Troubleshooting

### Issue: "File not found" when quarantining
**Solution:** Ensure file path is absolute and file exists with read permissions.

### Issue: "Failed to delete original file"
**Solution:** Check file permissions. Quarantine still succeeds but warns about deletion failure.

### Issue: "Database locked"
**Solution:** Ensure only one backend instance is running. SQLite doesn't support concurrent writes.

### Issue: Encryption key error
**Solution:** Set `QUARANTINE_ENCRYPTION_KEY` in environment or let system generate random key (not recommended for production).

---

## 🔄 Migration from Demo Mode

**Before (Simulated):**
- In-memory array storage
- No file operations
- Lost on server restart
- Hardcoded demo data

**After (Real Implementation):**
- ✅ Persistent SQLite database
- ✅ Actual file encryption and storage
- ✅ Survives server restarts
- ✅ Real threat detection integration

**No manual migration needed** - Old demo data is automatically replaced with real quarantine system.

---

## 📝 Best Practices

1. **Regular Cleanup:** Schedule automatic cleanup of old quarantine files (30+ days)
2. **Backup Database:** Regularly backup `quarantine.db` for disaster recovery
3. **Monitor Disk Usage:** Quarantine vault can grow large - monitor disk space
4. **Secure Encryption Key:** Use environment variables, never hardcode keys
5. **Permission Handling:** Ensure backend process has write access to quarantine vault
6. **User Notifications:** Alert users when files are quarantined automatically
7. **Audit Logging:** Log all quarantine operations for security audits

---

## 🎉 Summary

Your Nebula Shield antivirus now has a **fully functional, production-ready quarantine system**:

✅ **Real file quarantine** with encryption  
✅ **Persistent storage** (SQLite database)  
✅ **Secure restoration** with decryption  
✅ **Bulk operations** for managing multiple files  
✅ **Statistics & reporting** for monitoring  
✅ **Automatic cleanup** of old files  

**No more simulations** - this is the real deal! 🚀
