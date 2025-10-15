# Advanced Features Documentation

This document provides comprehensive information about the advanced features added to Nebula Shield Anti-Virus.

## Table of Contents
1. [Bulk Operations](#bulk-operations)
2. [Scheduled Tasks](#scheduled-tasks)
3. [Settings Import/Export](#settings-importexport)
4. [Cloud Backup](#cloud-backup)

---

## Bulk Operations

Execute operations on multiple items in parallel with real-time progress tracking.

### Features
- **Parallel Processing**: Process multiple items simultaneously (configurable concurrency, default: 5)
- **Real-time Progress**: Track progress per item and overall operation
- **Operation Types**: scan, delete, restore, quarantine
- **Status Tracking**: pending → processing → completed/failed/cancelled
- **Export Results**: Export operation results to JSON or CSV format
- **Statistics**: View operation stats and averages
- **Auto Cleanup**: Automatically removes operations older than 24 hours

### API Endpoints

#### Create Operation
```http
POST /api/bulk/operations
Content-Type: application/json

{
  "type": "scan",
  "items": ["file1.exe", "file2.dll", "file3.sys"],
  "options": {
    "concurrency": 5,
    "priority": "high"
  }
}
```

**Response:**
```json
{
  "id": "op_1234567890",
  "type": "scan",
  "status": "pending",
  "totalItems": 3,
  "processedItems": 0,
  "successfulItems": 0,
  "failedItems": 0,
  "progress": 0,
  "createdAt": "2024-01-15T10:30:00.000Z"
}
```

#### Execute Operation
```http
POST /api/bulk/operations/:id/execute
Content-Type: application/json

{
  "processor": "scan" // or custom processor function
}
```

#### Cancel Operation
```http
POST /api/bulk/operations/:id/cancel
```

#### Get Operation Status
```http
GET /api/bulk/operations/:id
```

#### List All Operations
```http
GET /api/bulk/operations
```

#### Get Statistics
```http
GET /api/bulk/statistics
```

**Response:**
```json
{
  "totalOperations": 15,
  "completedOperations": 12,
  "failedOperations": 2,
  "cancelledOperations": 1,
  "averageDuration": 5234,
  "totalItemsProcessed": 1532,
  "successRate": 94.5
}
```

#### Export Results
```http
GET /api/bulk/operations/:id/export?format=json
```

Formats: `json`, `csv`

#### Delete Operation
```http
DELETE /api/bulk/operations/:id
```

### Events
The bulk operations service emits the following events:

- `operation:created` - When operation is created
- `operation:started` - When operation starts executing
- `operation:completed` - When operation completes successfully
- `operation:failed` - When operation fails
- `operation:cancelled` - When operation is cancelled
- `item:completed` - When individual item completes
- `item:failed` - When individual item fails
- `operation:progress` - Progress updates during execution

### Usage Example

```javascript
// Create a bulk scan operation
const response = await fetch('http://localhost:8080/api/bulk/operations', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    type: 'scan',
    items: ['file1.exe', 'file2.dll', 'file3.sys'],
    options: { concurrency: 3 }
  })
});

const operation = await response.json();

// Execute the operation
await fetch(`http://localhost:8080/api/bulk/operations/${operation.id}/execute`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ processor: 'scan' })
});

// Monitor progress
const interval = setInterval(async () => {
  const status = await fetch(`http://localhost:8080/api/bulk/operations/${operation.id}`)
    .then(r => r.json());
  
  console.log(`Progress: ${status.progress}%`);
  
  if (status.status === 'completed' || status.status === 'failed') {
    clearInterval(interval);
    console.log('Operation finished:', status);
  }
}, 1000);
```

---

## Scheduled Tasks

Automate recurring tasks with cron-based scheduling.

### Features
- **Cron Scheduling**: Use cron expressions for flexible scheduling
- **Task Types**: scan, cleanup, backup, update, custom
- **Persistent Storage**: Tasks saved to JSON file (data/scheduled-tasks.json)
- **Execution History**: Track last 1000 executions with 7-day retention
- **Enable/Disable**: Toggle tasks without deleting them
- **Manual Execution**: Run tasks on-demand
- **Import/Export**: Backup and restore task configurations
- **Statistics**: View success rates and task analytics

### API Endpoints

#### Create Task
```http
POST /api/tasks
Content-Type: application/json

{
  "name": "Daily System Scan",
  "type": "scan",
  "schedule": "0 2 * * *",
  "enabled": true,
  "options": {
    "scanType": "full",
    "priority": "high"
  }
}
```

**Cron Schedule Format:**
```
* * * * *
│ │ │ │ │
│ │ │ │ └─── Day of week (0-6, Sunday=0)
│ │ │ └───── Month (1-12)
│ │ └─────── Day of month (1-31)
│ └───────── Hour (0-23)
└─────────── Minute (0-59)
```

**Common Schedules:**
- `0 2 * * *` - Daily at 2:00 AM
- `*/15 * * * *` - Every 15 minutes
- `0 0 * * 0` - Weekly on Sunday at midnight
- `0 0 1 * *` - Monthly on the 1st at midnight

#### List All Tasks
```http
GET /api/tasks
```

#### Get Task Details
```http
GET /api/tasks/:id
```

#### Update Task
```http
PUT /api/tasks/:id
Content-Type: application/json

{
  "schedule": "0 3 * * *",
  "options": {
    "scanType": "quick"
  }
}
```

#### Delete Task
```http
DELETE /api/tasks/:id
```

#### Execute Task Manually
```http
POST /api/tasks/:id/execute
```

#### Enable/Disable Task
```http
PUT /api/tasks/:id/toggle
```

#### Get Execution History
```http
GET /api/tasks/:id/history?limit=50
```

**Response:**
```json
[
  {
    "taskId": "task_1234567890",
    "taskName": "Daily System Scan",
    "status": "success",
    "startTime": "2024-01-15T02:00:00.000Z",
    "endTime": "2024-01-15T02:15:32.000Z",
    "duration": 932000,
    "result": {
      "filesScanned": 45678,
      "threatsFound": 2
    }
  }
]
```

#### Get Statistics
```http
GET /api/tasks/statistics
```

**Response:**
```json
{
  "totalTasks": 5,
  "enabledTasks": 4,
  "disabledTasks": 1,
  "totalExecutions": 127,
  "successfulExecutions": 125,
  "failedExecutions": 2,
  "successRate": 98.4,
  "tasksByType": {
    "scan": 2,
    "cleanup": 1,
    "backup": 1,
    "update": 1
  },
  "averageExecutionTime": 15234
}
```

#### Import Tasks
```http
POST /api/tasks/import
Content-Type: application/json

{
  "tasks": [...],
  "overwrite": false
}
```

#### Export Tasks
```http
GET /api/tasks/export
```

### Task Types

**1. Scan**
```json
{
  "type": "scan",
  "options": {
    "scanType": "quick|full",
    "targets": ["C:\\", "D:\\"]
  }
}
```

**2. Cleanup**
```json
{
  "type": "cleanup",
  "options": {
    "cleanQuarantine": true,
    "cleanLogs": true,
    "olderThan": 30
  }
}
```

**3. Backup**
```json
{
  "type": "backup",
  "options": {
    "destination": "cloud|local",
    "encrypt": true
  }
}
```

**4. Update**
```json
{
  "type": "update",
  "options": {
    "updateDefinitions": true,
    "updateSoftware": false
  }
}
```

**5. Custom**
```json
{
  "type": "custom",
  "options": {
    "handler": "customFunctionName",
    "params": {...}
  }
}
```

### Events

- `task:created` - When task is created
- `task:updated` - When task is updated
- `task:deleted` - When task is deleted
- `task:started` - When task execution starts
- `task:completed` - When task completes successfully
- `task:failed` - When task execution fails

---

## Settings Import/Export

Backup, restore, and transfer application settings.

### Features
- **Export Settings**: Export all settings with SHA-256 checksum validation
- **Import Settings**: Import with merge or replace modes
- **Encryption**: AES-256-CBC encryption support for sensitive data
- **Automatic Backups**: Creates backup before import/reset (max 10, auto cleanup)
- **Backup Management**: List, restore, and delete backups
- **Compare Settings**: Find differences between settings
- **Reset to Defaults**: Restore factory settings
- **Export Formats**: JSON (pretty) or compact

### API Endpoints

#### Export Settings
```http
POST /api/settings/export
Content-Type: application/json

{
  "userId": "user123",
  "encrypt": true,
  "password": "secure-password"
}
```

**Response:**
```json
{
  "metadata": {
    "exportDate": "2024-01-15T10:30:00.000Z",
    "appVersion": "1.0.0",
    "userId": "user123",
    "checksum": "abc123...",
    "encrypted": true
  },
  "settings": {...},
  "customRules": [...],
  "whitelist": [...],
  "blacklist": [...]
}
```

#### Export to File
```http
POST /api/settings/export/file
Content-Type: application/json

{
  "filePath": "C:\\backups\\settings-backup.json",
  "options": {
    "format": "json",
    "encrypt": false
  }
}
```

#### Import Settings
```http
POST /api/settings/import
Content-Type: application/json

{
  "importData": {...},
  "options": {
    "merge": true,
    "skipBackup": false,
    "encrypted": true,
    "password": "secure-password"
  }
}
```

**Options:**
- `merge`: Merge with existing settings (true) or replace (false)
- `skipBackup`: Skip creating pre-import backup
- `skipChecksumValidation`: Skip checksum verification (not recommended)

#### Import from File
```http
POST /api/settings/import/file
Content-Type: application/json

{
  "filePath": "C:\\backups\\settings-backup.json",
  "options": {
    "merge": false,
    "encrypted": true,
    "password": "secure-password"
  }
}
```

#### Create Backup
```http
POST /api/settings/backups
Content-Type: application/json

{
  "label": "Before Major Update"
}
```

#### List Backups
```http
GET /api/settings/backups
```

**Response:**
```json
[
  {
    "id": "backup_1234567890",
    "timestamp": "2024-01-15T10:30:00.000Z",
    "label": "Before Major Update",
    "size": 15234,
    "encrypted": false
  }
]
```

#### Restore Backup
```http
POST /api/settings/backups/:id/restore
Content-Type: application/json

{
  "merge": false,
  "createBackupBeforeRestore": true
}
```

#### Delete Backup
```http
DELETE /api/settings/backups/:id
```

#### Compare Settings
```http
POST /api/settings/compare
Content-Type: application/json

{
  "settings1": {...},
  "settings2": {...}
}
```

**Response:**
```json
{
  "added": {
    "general.newSetting": "value"
  },
  "removed": {
    "general.oldSetting": "value"
  },
  "changed": {
    "scanner.sensitivity": {
      "old": "medium",
      "new": "high"
    }
  }
}
```

#### Reset to Defaults
```http
POST /api/settings/reset
Content-Type: application/json

{
  "categories": ["general", "scanner"],
  "createBackup": true
}
```

### Setting Categories

1. **general** - Application language, theme, startup behavior
2. **scanner** - Scan sensitivity, exclusions, file types
3. **protection** - Real-time protection, firewall, web protection
4. **notifications** - Email, desktop, sound alerts
5. **appearance** - UI theme, colors, layout
6. **advanced** - Performance, logging, debugging
7. **privacy** - Data collection, telemetry, cloud sync

---

## Cloud Backup

Backup and restore your data to cloud storage providers.

### Supported Providers

| Provider | Max File Size | Features |
|----------|--------------|----------|
| AWS S3 | 5 GB | Encryption, Versioning, Lifecycle |
| Google Drive | 5 GB | Encryption, Sharing |
| Dropbox | 350 MB | Encryption, Versioning |
| OneDrive | 250 MB | Encryption, Versioning |
| FTP/SFTP | Unlimited | Encryption |

### Features
- **Multi-Provider Support**: Connect to multiple cloud providers
- **Encrypted Credentials**: AES-256-CBC encryption for stored credentials
- **ZIP Compression**: Automatic compression using archiver library
- **Progress Tracking**: Real-time progress (0-50% packaging, 50-100% uploading)
- **Backup Contents**: Settings, quarantine, logs, database, custom files
- **Connection Testing**: Verify connectivity with latency measurement
- **Statistics**: Track backup count and total size per provider
- **Restore Functionality**: Download and extract backups

### API Endpoints

#### List Providers
```http
GET /api/cloud/providers
```

**Response:**
```json
[
  {
    "id": "s3",
    "name": "AWS S3",
    "connected": false,
    "maxFileSize": 5368709120,
    "features": ["encryption", "versioning", "lifecycle"]
  }
]
```

#### Connect Provider
```http
POST /api/cloud/providers/:id/connect
Content-Type: application/json

// AWS S3
{
  "apiKey": "AWS_ACCESS_KEY",
  "secretKey": "AWS_SECRET_KEY",
  "bucket": "my-backup-bucket",
  "region": "us-east-1"
}

// Google Drive
{
  "accessToken": "google-oauth-token",
  "refreshToken": "google-refresh-token"
}

// Dropbox
{
  "accessToken": "dropbox-access-token"
}

// OneDrive
{
  "accessToken": "onedrive-access-token"
}

// FTP/SFTP
{
  "host": "ftp.example.com",
  "port": 21,
  "username": "user",
  "password": "pass",
  "protocol": "sftp"
}
```

#### Disconnect Provider
```http
POST /api/cloud/providers/:id/disconnect
```

#### Test Connection
```http
POST /api/cloud/providers/:id/test
```

**Response:**
```json
{
  "connected": true,
  "latency": 125,
  "provider": "s3",
  "testedAt": "2024-01-15T10:30:00.000Z"
}
```

#### Create Cloud Backup
```http
POST /api/cloud/backups
Content-Type: application/json

{
  "name": "Full System Backup",
  "providerId": "s3",
  "files": ["settings", "quarantine", "logs", "database"],
  "encrypt": true,
  "compress": true,
  "includeSettings": true,
  "includeQuarantine": true,
  "includeLogs": true,
  "includeDatabase": true
}
```

**Progress Events:**
The backup will emit progress events with the following structure:
```json
{
  "id": "backup_1234567890",
  "progress": 25,
  "stage": "packaging"
}
```

Progress stages:
- **packaging** (0-50%): Creating ZIP archive
- **uploading** (50-100%): Uploading to cloud

#### List Cloud Backups
```http
GET /api/cloud/backups?providerId=s3
```

**Response:**
```json
[
  {
    "id": "backup_1234567890",
    "name": "Full System Backup",
    "providerId": "s3",
    "size": 45678901,
    "createdAt": "2024-01-15T10:30:00.000Z",
    "files": ["settings", "quarantine", "logs", "database"],
    "encrypted": true
  }
]
```

#### Restore Backup
```http
POST /api/cloud/backups/:id/restore
Content-Type: application/json

{
  "restoreSettings": true,
  "restoreQuarantine": true,
  "restoreLogs": false,
  "restoreDatabase": true,
  "overwrite": false
}
```

#### Delete Cloud Backup
```http
DELETE /api/cloud/backups/:id
```

#### Get Statistics
```http
GET /api/cloud/statistics
```

**Response:**
```json
{
  "totalBackups": 15,
  "totalSize": 5368709120,
  "byProvider": {
    "s3": {
      "count": 10,
      "size": 4294967296
    },
    "googleDrive": {
      "count": 5,
      "size": 1073741824
    }
  },
  "lastBackup": "2024-01-15T10:30:00.000Z"
}
```

### Events

- `provider:connected` - When provider is connected
- `provider:disconnected` - When provider is disconnected
- `backup:created` - When backup is initialized
- `backup:progress` - Progress updates during packaging/uploading
- `backup:completed` - When backup completes successfully
- `backup:failed` - When backup fails
- `restore:started` - When restore begins
- `restore:completed` - When restore completes
- `restore:failed` - When restore fails

### Best Practices

1. **Regular Backups**: Schedule automatic cloud backups using Scheduled Tasks
2. **Multiple Providers**: Use different providers for redundancy
3. **Encryption**: Always encrypt backups containing sensitive data
4. **Test Restores**: Periodically test restore functionality
5. **Monitor Storage**: Keep track of cloud storage usage
6. **Cleanup Old Backups**: Remove outdated backups to save space

### Error Handling

All API endpoints return appropriate HTTP status codes:

- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request data
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

Error responses include a descriptive message:
```json
{
  "error": "Provider not connected. Please connect to the provider first."
}
```

---

## Integration Examples

### Example 1: Automated Daily Backup with Cloud Storage

```javascript
// Step 1: Connect to cloud provider
await fetch('http://localhost:8080/api/cloud/providers/s3/connect', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    apiKey: 'YOUR_AWS_KEY',
    secretKey: 'YOUR_AWS_SECRET',
    bucket: 'nebula-backups',
    region: 'us-east-1'
  })
});

// Step 2: Create scheduled backup task
await fetch('http://localhost:8080/api/tasks', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'Daily Cloud Backup',
    type: 'backup',
    schedule: '0 2 * * *', // Daily at 2 AM
    enabled: true,
    options: {
      destination: 'cloud',
      providerId: 's3',
      encrypt: true,
      includeSettings: true,
      includeQuarantine: true,
      includeLogs: true,
      includeDatabase: true
    }
  })
});
```

### Example 2: Bulk Scan with Progress Monitoring

```javascript
// Step 1: Create bulk operation
const createResponse = await fetch('http://localhost:8080/api/bulk/operations', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    type: 'scan',
    items: suspiciousFiles,
    options: { concurrency: 10 }
  })
});

const operation = await createResponse.json();

// Step 2: Execute operation
await fetch(`http://localhost:8080/api/bulk/operations/${operation.id}/execute`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ processor: 'scan' })
});

// Step 3: Monitor progress
const progressInterval = setInterval(async () => {
  const statusResponse = await fetch(
    `http://localhost:8080/api/bulk/operations/${operation.id}`
  );
  const status = await statusResponse.json();
  
  updateProgressBar(status.progress);
  
  if (status.status === 'completed') {
    clearInterval(progressInterval);
    
    // Export results
    const resultsResponse = await fetch(
      `http://localhost:8080/api/bulk/operations/${operation.id}/export?format=csv`
    );
    const results = await resultsResponse.json();
    downloadFile(results.data, 'scan-results.csv');
  }
}, 1000);
```

### Example 3: Settings Migration

```javascript
// Step 1: Export settings from old installation
const exportResponse = await fetch('http://localhost:8080/api/settings/export', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    userId: 'user123',
    encrypt: true,
    password: 'migration-password'
  })
});

const exportedSettings = await exportResponse.json();

// Step 2: Transfer to new installation and import
await fetch('http://new-installation:8080/api/settings/import', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    importData: exportedSettings,
    options: {
      merge: false, // Replace all settings
      encrypted: true,
      password: 'migration-password'
    }
  })
});
```

---

## Dependencies

The advanced features require the following npm packages:

```json
{
  "dependencies": {
    "node-cron": "^3.0.3",
    "archiver": "^6.0.1"
  }
}
```

Install with:
```bash
npm install node-cron archiver
```

---

## File Structure

```
nebula-shield-anti-virus/
├── backend/
│   ├── bulk-operations.js       # Bulk operations service
│   ├── scheduled-tasks.js       # Scheduled tasks service
│   ├── settings-import-export.js # Settings import/export service
│   └── cloud-backup.js          # Cloud backup service
├── data/
│   ├── scheduled-tasks.json     # Persistent task storage
│   ├── settings.json            # Application settings
│   └── settings-backups/        # Settings backup files
└── temp/
    └── cloud-backups/           # Temporary backup packages
```

---

## Security Considerations

1. **Credential Encryption**: All cloud provider credentials are encrypted using AES-256-CBC
2. **Backup Encryption**: Optional AES-256-CBC encryption for backup data
3. **Checksum Validation**: SHA-256 checksums verify settings integrity
4. **Secure Passwords**: Use strong passwords for encrypted exports/imports
5. **Access Control**: Implement authentication and authorization in production
6. **HTTPS**: Use HTTPS in production environments
7. **Rate Limiting**: Implement rate limiting for API endpoints
8. **Input Validation**: All user inputs are validated and sanitized

---

## Troubleshooting

### Bulk Operations

**Problem**: Operations stuck in "pending" status
- **Solution**: Call the execute endpoint to start processing

**Problem**: High memory usage during bulk operations
- **Solution**: Reduce concurrency value in options

### Scheduled Tasks

**Problem**: Tasks not executing at scheduled time
- **Solution**: Verify cron expression format and task enabled status

**Problem**: Task history not showing recent executions
- **Solution**: Check if history cleanup threshold has been exceeded (7 days)

### Settings Import/Export

**Problem**: Import fails with checksum error
- **Solution**: Use `skipChecksumValidation: true` if file was manually edited

**Problem**: Cannot decrypt encrypted settings
- **Solution**: Verify correct password is being used

### Cloud Backup

**Problem**: Backup fails during upload
- **Solution**: Check provider connection, file size limits, and network connectivity

**Problem**: Restore fails with file not found
- **Solution**: Verify backup ID and provider connection status

---

## Performance Metrics

### Bulk Operations
- **Throughput**: Up to 1000 items/minute (depends on operation type)
- **Concurrency**: 1-20 (recommended: 5-10)
- **Memory**: ~50MB + (concurrency * item_size)

### Scheduled Tasks
- **Task Limit**: Unlimited
- **Execution Accuracy**: ±1 second of scheduled time
- **History Storage**: Last 1000 executions, 7-day retention

### Settings Import/Export
- **Export Time**: ~100ms for typical settings
- **Import Time**: ~200ms with merge, ~150ms with replace
- **Backup Storage**: Max 10 backups, ~1MB each

### Cloud Backup
- **Compression Ratio**: ~60-80% (depends on data)
- **Upload Speed**: Depends on provider and network
- **Package Time**: ~1-5 seconds for typical backup

---

## Future Enhancements

- [ ] WebSocket support for real-time progress updates
- [ ] Multi-file upload for bulk operations
- [ ] Settings diff visualization UI
- [ ] Cloud backup scheduling templates
- [ ] Incremental backups
- [ ] Backup versioning and rollback
- [ ] Azure Blob Storage support
- [ ] Custom task plugins
- [ ] Email notifications for task completion
- [ ] Advanced filtering for operation history

---

## Support

For issues, questions, or feature requests, please contact the development team or create an issue in the project repository.

**Last Updated**: January 2024
**Version**: 1.0.0
