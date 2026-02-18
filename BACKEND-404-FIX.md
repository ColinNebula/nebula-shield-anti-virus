# Backend Server - Error 404 Fix

## Problem Summary
When running the Electron app in production mode, you may see this error in the console:
```
Error getting protection status: Error: HTTP error! status: 404
```

## Root Causes Identified

### 1. Backend Server Not Running
The most common cause is that the backend server (auth-server.js) is not running on port 8080.

**Solution:** Start the backend server using one of these methods:

#### Method A: Using the Batch File (Recommended)
```batch
START-BACKEND.bat
```

#### Method B: Using PowerShell with Start-Process
```powershell
$backendPath = "Z:\Directory\projects\nebula-shield-anti-virus\backend"
Start-Process -NoNewWindow -FilePath "node" -ArgumentList "auth-server.js" -WorkingDirectory $backendPath
```

#### Method C: Direct Node Command (May have issues with SIGINT)
```powershell
cd backend
node auth-server.js
```

> **Note:** Method C may cause the server to immediately shutdown due to SIGINT signal handling. Use Method A or B instead.

### 2. Duplicate API Endpoints
There were two `/api/status` endpoints defined in `backend/auth-server.js`, causing route conflicts.

**Fix Applied:** Removed the duplicate endpoint at line ~1584. Now only one `/api/status` endpoint exists (around line 995).

### 3. API Base URL Configuration
The frontend (`src/services/antivirusApi.js`) automatically detects whether it's running in Electron mode:

```javascript
const isElectron = typeof window !== 'undefined' && window.electronAPI?.isElectron;
const API_BASE_URL = isElectron ? 'http://localhost:8080/api' : '/api';
```

- **In Electron (Production):** Connects directly to `http://localhost:8080/api`
- **In Development (React Dev Server):** Uses proxy at `/api` → `http://localhost:8080/api`

## How to Verify the Fix

### Step 1: Ensure Backend is Running
```powershell
# Check if backend is listening on port 8080
Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
```

### Step 2: Test Backend Health Endpoint
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/health"
```

Expected response:
```json
{
  "status": "healthy",
  "service": "Nebula Shield Auth Server",
  "timestamp": "2025-10-26T22:15:06.930Z",
  "uptime": 47.5,
  "port": 8080
}
```

### Step 3: Test Protection Status Endpoint
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/status"
```

Expected response:
```json
{
  "protection_enabled": true,
  "real_time_protection": true,
  "total_scanned_files": 12370,
  "total_threats_found": 40,
  "quarantined_files": 7,
  "last_scan_time": "2025-10-26T21:15:23.145Z",
  "last_update": "2025-10-26T20:15:23.145Z",
  "version": "1.0.0",
  "signature_count": 50428
}
```

## Quick Reference

### Start Backend Server
```batch
START-BACKEND.bat
```

### Stop Backend Server
```batch
STOP-BACKEND.bat
```

### Check Server Status
```powershell
# Check if running
Get-Process -Name node -ErrorAction SilentlyContinue

# Check port
Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue

# Test health
Invoke-RestMethod -Uri "http://localhost:8080/api/health"
```

### Development Workflow
1. Start backend: `START-BACKEND.bat`
2. Start frontend: `npm start` (dev mode) or `npm run electron:dev` (Electron mode)
3. Make changes
4. Stop backend when done: `STOP-BACKEND.bat`

### Production Build Workflow
1. Ensure backend is running: `START-BACKEND.bat`
2. Run health checks: `npm run check:servers`
3. Build: `npm run electron:build:win`
4. Test the installer

## Technical Details

### Backend Ports
- **Backend API Server:** Port 8080
- **Frontend Dev Server:** Port 3000 (development only)
- **Electron Local Server:** Port 3003 (production, serves built files)

### How It Works in Production
1. Electron starts a local Express server on port 3003 to serve the built React files
2. React app loads in the Electron window from `http://127.0.0.1:3003`
3. Frontend detects it's running in Electron via `window.electronAPI.isElectron`
4. API calls are made directly to `http://localhost:8080/api`
5. Backend server on port 8080 handles all API requests

### API Endpoints
- `/api/health` - Server health check
- `/api/status` - Protection status (for dashboard)
- `/api/scan/quick` - Quick scan
- `/api/scan/full` - Full system scan
- `/api/disk/*` - Disk cleanup endpoints
- And many more...

## Troubleshooting

### Error: "Cannot connect to backend"
- Check if backend is running: `Get-Process -Name node`
- Start backend: `START-BACKEND.bat`
- Verify port 8080 is not blocked by firewall

### Error: "Port 8080 already in use"
- Stop all node processes: `STOP-BACKEND.bat`
- Or kill specific process: `Stop-Process -Id <PID> -Force`

### Error: "404 on API calls"
- Ensure backend is running
- Check backend logs for errors
- Verify API endpoint exists in `backend/auth-server.js`
- Test endpoint directly: `Invoke-RestMethod -Uri "http://localhost:8080/api/<endpoint>"`

### Backend Shuts Down Immediately
- Don't use `node auth-server.js` in a terminal that will close
- Use `START-BACKEND.bat` instead
- Or use `Start-Process` with `-NoNewWindow` flag

## Files Modified
- `backend/auth-server.js` - Removed duplicate `/api/status` endpoint
- `START-BACKEND.bat` - New: Easy backend startup script
- `STOP-BACKEND.bat` - New: Easy backend shutdown script
- `BACKEND-404-FIX.md` - This documentation

## Related Documentation
- `SERVER-MANAGEMENT.md` - Server health checks and management
- `DEPLOYMENT-GUIDE.md` - Full deployment instructions
- `ELECTRON_README.md` - Electron-specific configuration
