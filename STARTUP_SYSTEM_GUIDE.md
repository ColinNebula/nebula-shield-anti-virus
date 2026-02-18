# 🚀 Nebula Shield Anti-Virus - Complete Startup System

## Overview

The complete startup system ensures all necessary servers, backends, and services are properly initialized before launching the Nebula Shield Anti-Virus application.

---

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Startup Scripts](#startup-scripts)
3. [Required Services](#required-services)
4. [Startup Process](#startup-process)
5. [Development vs Production](#development-vs-production)
6. [Troubleshooting](#troubleshooting)
7. [Port Configuration](#port-configuration)
8. [Service Management](#service-management)

---

## 🎯 Quick Start

### Production Mode (Recommended)
```powershell
# Double-click START-COMPLETE-APP.bat
# Or run in PowerShell:
.\START-COMPLETE-APP.ps1
```

### Development Mode
```powershell
.\START-COMPLETE-APP.ps1 -Development
```

### Stop All Services
```powershell
.\STOP-ALL-SERVICES.ps1
# Or double-click STOP-ALL-SERVICES.bat
```

---

## 📂 Startup Scripts

### Primary Scripts

#### **START-COMPLETE-APP.ps1** (Main Startup Script)
- **Purpose**: Master startup orchestrator
- **Features**:
  - ✅ System requirements validation
  - ✅ Automatic dependency installation
  - ✅ Database verification
  - ✅ Port cleanup and conflict resolution
  - ✅ Sequential service startup
  - ✅ Health checks for all services
  - ✅ Automatic failure detection
  - ✅ Application launch

#### **START-COMPLETE-APP.bat** (Windows Wrapper)
- **Purpose**: Windows-friendly double-click launcher
- **Action**: Calls START-COMPLETE-APP.ps1 with proper execution policy

#### **STOP-ALL-SERVICES.ps1** (Service Shutdown)
- **Purpose**: Gracefully stops all running services
- **Features**:
  - Stops all Node.js processes
  - Stops Electron processes
  - Stops C++ backend
  - Cleans up all ports
  - Provides confirmation

#### **STOP-ALL-SERVICES.bat** (Windows Wrapper)
- **Purpose**: Windows-friendly stop script

---

## 🔧 Required Services

### Core Backend Services

#### 1. **Mock Backend API** (Port 8080)
- **File**: `backend/mock-backend.js`
- **Purpose**: Primary REST API for application data
- **Endpoints**:
  - `/api/status` - Health check
  - `/api/scans` - Scan history
  - `/api/threats` - Threat data
  - `/api/quarantine` - Quarantine management
  - `/api/realtime-protection` - Protection status
  - `/api/scheduled-scans` - Scan scheduling
  - `/api/updates` - Update management
  - `/api/system` - System information
- **Required**: ✅ Yes
- **Startup Order**: 1st

#### 2. **Authentication Server** (Port 8082)
- **File**: `backend/auth-server.js`
- **Purpose**: User authentication and session management
- **Endpoints**:
  - `/api/auth/login` - User login
  - `/api/auth/register` - User registration
  - `/api/auth/logout` - User logout
  - `/api/auth/verify-token` - Token validation
  - `/api/auth/refresh-token` - Token refresh
  - `/api/auth/user` - User profile
  - `/api/auth/status` - Service health
- **Required**: ✅ Yes
- **Startup Order**: 2nd

#### 3. **C++ Backend** (Port 8080 - Alternative)
- **File**: `backend/build/bin/Release/nebula_shield_backend.exe`
- **Purpose**: High-performance native backend (optional)
- **Features**:
  - Low-level system scanning
  - Driver management
  - Performance-critical operations
- **Required**: ⚠️ Optional (falls back to Node.js)
- **Startup Order**: 3rd

#### 4. **Mobile Backend** (Port 3001)
- **File**: `mobile-backend/server.js`
- **Purpose**: Mobile app support (if enabled)
- **Required**: ⚠️ Optional
- **Startup Order**: 4th

### Frontend Services

#### 5. **Vite Dev Server** (Port 3002) - Development Only
- **Purpose**: Hot-reload development server
- **Features**:
  - Fast refresh
  - ES module support
  - Source maps
  - Dev tools integration
- **Required**: ✅ Yes (Development mode)
- **Startup Order**: 5th (Development)

#### 6. **Electron Application**
- **Purpose**: Desktop application wrapper
- **Modes**:
  - **Development**: Loads from Vite dev server (http://localhost:3002)
  - **Production**: Loads from built files
- **Required**: ✅ Yes
- **Startup Order**: Last

---

## 🔄 Startup Process

### Step-by-Step Flow

```
[1/6] System Requirements Check
      ├─ Verify Node.js installation
      ├─ Verify npm installation
      └─ Check Python (optional)

[2/6] Dependency Installation
      ├─ Install frontend dependencies (if needed)
      └─ Install backend dependencies (if needed)

[3/6] Database Verification
      ├─ Check for nebula_shield.db
      ├─ Verify signature count
      └─ Validate virus-signatures.json

[4/6] Port Cleanup
      ├─ Stop processes on port 3000 (old React)
      ├─ Stop processes on port 3002 (Vite)
      ├─ Stop processes on port 8080 (Mock Backend)
      ├─ Stop processes on port 8082 (Auth Server)
      └─ Stop processes on port 3001 (Mobile Backend)

[5/6] Start Backend Services
      ├─ Launch Mock Backend API (8080)
      │  └─ Wait for port to open (30s timeout)
      ├─ Launch Auth Server (8082)
      │  └─ Wait for port to open (30s timeout)
      ├─ Launch C++ Backend (optional)
      └─ Launch Mobile Backend (optional)

[6/6] Launch Application
      ├─ Development Mode:
      │  ├─ Start Vite dev server (3002)
      │  ├─ Wait for Vite initialization (45s timeout)
      │  └─ Launch Electron app
      └─ Production Mode:
         └─ Launch built executable
```

### Health Check Process

```
Service Startup
      │
      ├─ Start process in new window
      │
      ├─ Wait for port to open
      │  ├─ Check every 1 second
      │  └─ Timeout after 30-45 seconds
      │
      ├─ Verify port is listening
      │
      ├─ Test HTTP endpoint (if applicable)
      │  └─ Send test request
      │
      └─ Report success/failure
```

---

## 🏭 Development vs Production

### Development Mode (`-Development` flag)

**Command**:
```powershell
.\START-COMPLETE-APP.ps1 -Development
```

**Services Started**:
1. Mock Backend API (8080)
2. Auth Server (8082)
3. C++ Backend (optional)
4. Mobile Backend (optional)
5. **Vite Dev Server (3002)** ← Hot reload
6. Electron (loads from Vite)

**Features**:
- Hot module replacement
- Source maps enabled
- DevTools available
- Fast refresh on code changes
- Console logs visible

**Use Case**: Active development, testing, debugging

---

### Production Mode (Default)

**Command**:
```powershell
.\START-COMPLETE-APP.ps1
```

**Services Started**:
1. Mock Backend API (8080)
2. Auth Server (8082)
3. C++ Backend (optional)
4. Mobile Backend (optional)
5. Built Electron app (standalone .exe)

**Features**:
- Optimized builds
- No dev server overhead
- Production-ready performance
- Standalone executable

**Use Case**: End-user deployment, production testing

---

## 🐛 Troubleshooting

### Common Issues

#### Issue: "Port already in use"
**Symptoms**: Service fails to start, error message about port conflict

**Solutions**:
```powershell
# Stop all services first
.\STOP-ALL-SERVICES.ps1

# Then restart
.\START-COMPLETE-APP.ps1
```

**Manual Port Cleanup**:
```powershell
# Find process on port 8080
Get-NetTCPConnection -LocalPort 8080 | Select-Object -ExpandProperty OwningProcess

# Kill specific process
Stop-Process -Id <PID> -Force
```

---

#### Issue: "Node.js not found"
**Symptoms**: Script exits immediately with error

**Solution**:
1. Install Node.js from https://nodejs.org/
2. Recommended version: 18.x or higher
3. Restart terminal after installation
4. Verify: `node --version`

---

#### Issue: "Service timeout"
**Symptoms**: "Waiting for X to start... ✗ (Timeout)"

**Solutions**:
1. **Check service logs** - Look at the service window for errors
2. **Verify dependencies**:
   ```powershell
   cd backend
   npm install
   ```
3. **Run service manually** to see errors:
   ```powershell
   cd backend
   node mock-backend.js
   ```
4. **Check firewall** - Ensure Node.js is allowed
5. **Increase timeout** - Edit START-COMPLETE-APP.ps1 and increase timeout values

---

#### Issue: "Database not found"
**Symptoms**: Warning about missing database

**Solution**:
This is normal on first run. The database will be created automatically when the application starts.

**Manual Database Creation** (optional):
```powershell
cd backend
node -e "require('./mock-backend.js')"
```

---

#### Issue: "Built application not found"
**Symptoms**: In production mode, app doesn't launch

**Solution**:
Build the application first:
```powershell
npm run electron:build:win
```

Or use development mode instead:
```powershell
.\START-COMPLETE-APP.ps1 -Development
```

---

#### Issue: "Authentication fails"
**Symptoms**: Cannot log in to application

**Solutions**:
1. **Verify Auth Server is running** - Check port 8082
2. **Use default credentials**:
   - Email: `your-account@example.com`
   - Password: `Nebula2025!`
3. **Check Auth Server logs** - Look at Auth Server window
4. **Reset database** (last resort):
   ```powershell
   Remove-Item backend\data\nebula_shield.db
   .\START-COMPLETE-APP.ps1
   ```

---

#### Issue: "Services keep crashing"
**Symptoms**: Service windows close immediately

**Diagnostic Steps**:
1. **Run service manually** to see errors:
   ```powershell
   cd backend
   node mock-backend.js
   ```
2. **Check Node.js version**: Must be 16.x or higher
3. **Reinstall dependencies**:
   ```powershell
   Remove-Item node_modules -Recurse -Force
   Remove-Item backend\node_modules -Recurse -Force
   npm install
   cd backend
   npm install
   ```
4. **Check for syntax errors** in service files

---

## 🌐 Port Configuration

### Port Mapping

| Port | Service | Required | Protocol | Purpose |
|------|---------|----------|----------|---------|
| 3000 | React Dev (Legacy) | ❌ No | HTTP | Old development server |
| 3001 | Mobile Backend | ⚠️ Optional | HTTP | Mobile app support |
| 3002 | Vite Dev Server | ✅ Dev Only | HTTP | Hot-reload development |
| 5173 | Vite (Alternative) | ⚠️ Optional | HTTP | Vite fallback port |
| 8080 | Mock Backend API | ✅ Yes | HTTP | Main REST API |
| 8081 | Auth Server (Legacy) | ❌ No | HTTP | Old auth server |
| 8082 | Auth Server | ✅ Yes | HTTP | Authentication |

### Changing Ports

To change service ports, edit the following files:

**Backend Services** (`backend/mock-backend.js`, `backend/auth-server.js`):
```javascript
const PORT = process.env.PORT || 8080; // Change this
```

**Vite Dev Server** (`vite.config.js`):
```javascript
export default defineConfig({
  server: {
    port: 3002, // Change this
  },
});
```

**Update Startup Script** (`START-COMPLETE-APP.ps1`):
```powershell
# Update port numbers in:
# - Stop-ProcessOnPort calls
# - Wait-ForPort calls
# - Service start commands
```

---

## 🔧 Service Management

### Viewing Service Logs

Each service runs in its own PowerShell window with a labeled title:

- **Mock Backend API** - "Nebula Shield - Mock Backend API"
- **Auth Server** - "Nebula Shield - Auth Server"
- **Vite Dev Server** - "Nebula Shield - Vite Dev Server"
- **Mobile Backend** - "Nebula Shield - Mobile Backend"

**To view logs**: Switch to the corresponding window

---

### Stopping Individual Services

**Option 1: Close the service window**
- Each service runs in a separate window
- Closing the window stops that service

**Option 2: Kill by port**
```powershell
# Find process on port
Get-NetTCPConnection -LocalPort 8080 | Select-Object -ExpandProperty OwningProcess

# Kill process
Stop-Process -Id <PID> -Force
```

**Option 3: Use STOP-ALL-SERVICES.ps1**
- Stops all services at once

---

### Restarting Services

**Full Restart**:
```powershell
.\STOP-ALL-SERVICES.ps1
.\START-COMPLETE-APP.ps1
```

**Individual Service Restart**:
1. Close the service window (or kill the process)
2. Manually restart the service:
   ```powershell
   cd backend
   node mock-backend.js
   # Or
   node auth-server.js
   ```

---

### Service Health Monitoring

**Manual Health Checks**:

```powershell
# Check Mock Backend API
Invoke-WebRequest http://localhost:8080/api/status

# Check Auth Server
Invoke-WebRequest http://localhost:8082/api/auth/status

# Check Mobile Backend (if enabled)
Invoke-WebRequest http://localhost:3001/api/status

# Check Vite Dev Server (development mode)
Invoke-WebRequest http://localhost:3002
```

**Automated Monitoring** (built into startup script):
- Startup script automatically checks each service after launching
- Waits for ports to open (30-45 second timeout)
- Tests HTTP endpoints to verify functionality
- Reports success/failure for each service

---

## 📊 Advanced Options

### Verbose Mode

Enable detailed logging:
```powershell
.\START-COMPLETE-APP.ps1 -Verbose
```

Shows additional information:
- Detailed version numbers
- Optional service status
- Extended diagnostic information

---

### Skip Checks Mode

Skip system requirement checks (faster startup):
```powershell
.\START-COMPLETE-APP.ps1 -SkipChecks
```

⚠️ **Warning**: Only use if you know all requirements are met

---

### Custom Startup Configurations

Edit `START-COMPLETE-APP.ps1` to customize:

**Adjust Timeouts**:
```powershell
# Line ~XXX - Wait for service to start
if (Wait-ForPort 8080 "Mock Backend API" 30) {  # Change 30 to desired seconds
```

**Add Custom Services**:
```powershell
# Add after existing service starts
Write-Status "Starting Custom Service..." "Progress"
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd 'C:\path\to\service'; node custom-service.js"
)
```

**Disable Optional Services**:
```powershell
# Comment out sections you don't need:
# Mobile Backend (Port 3001)
<#
if (Test-Path $mobileBackendPath) {
    # ... startup code ...
}
#>
```

---

## 🎓 Best Practices

### For Development

1. **Always use Development mode**:
   ```powershell
   .\START-COMPLETE-APP.ps1 -Development
   ```

2. **Keep service windows open** to monitor logs

3. **Use Verbose mode** when debugging:
   ```powershell
   .\START-COMPLETE-APP.ps1 -Development -Verbose
   ```

4. **Restart services** after major code changes:
   ```powershell
   .\STOP-ALL-SERVICES.ps1
   .\START-COMPLETE-APP.ps1 -Development
   ```

---

### For Production Testing

1. **Build the application first**:
   ```powershell
   npm run electron:build:win
   ```

2. **Use Production mode**:
   ```powershell
   .\START-COMPLETE-APP.ps1
   ```

3. **Test with clean state**:
   ```powershell
   .\STOP-ALL-SERVICES.ps1
   # Wait 5 seconds
   .\START-COMPLETE-APP.ps1
   ```

---

### For End Users

1. **Create desktop shortcut** to `START-COMPLETE-APP.bat`

2. **Use built executable** once available:
   - Located in `dist/` folder after build
   - Or installed in `%LOCALAPPDATA%\Programs\nebula-shield-anti-virus`

3. **Stop services before shutdown**:
   ```powershell
   .\STOP-ALL-SERVICES.bat
   ```

---

## 📁 File Structure

```
nebula-shield-anti-virus/
│
├── START-COMPLETE-APP.ps1      # Main startup script (PowerShell)
├── START-COMPLETE-APP.bat      # Windows launcher
├── STOP-ALL-SERVICES.ps1       # Service shutdown script
├── STOP-ALL-SERVICES.bat       # Windows stop launcher
│
├── backend/
│   ├── mock-backend.js         # Main API server (Port 8080)
│   ├── auth-server.js          # Auth server (Port 8082)
│   ├── data/
│   │   ├── nebula_shield.db    # SQLite database
│   │   └── virus-signatures.json  # Virus signatures (475+)
│   └── node_modules/           # Backend dependencies
│
├── mobile-backend/             # Optional mobile support
│   └── server.js               # Mobile API (Port 3001)
│
├── src/                        # Frontend source code
├── electron/                   # Electron configuration
├── dist/                       # Built application
└── node_modules/               # Frontend dependencies
```

---

## 🔐 Security Considerations

### Default Credentials

**Production Deployment**: Change default credentials immediately!

**Location**: `backend/auth-server.js`
```javascript
const defaultUser = {
    email: "your-account@example.com",  // Change this
    password: "Nebula2025!",          // Change this
    // ...
};
```

### Port Security

- Services bind to `localhost` by default (not exposed externally)
- Firewall rules may be needed for Node.js on first run
- Consider using HTTPS in production (requires SSL certificates)

### Database Security

- `nebula_shield.db` contains user data and signatures
- Stored locally at `backend/data/nebula_shield.db`
- Backup regularly for data protection
- Do not expose database file to external access

---

## 📞 Support

### Quick Reference

| Issue | Solution |
|-------|----------|
| Port conflict | Run `STOP-ALL-SERVICES.ps1` first |
| Service won't start | Check service window for errors |
| Can't login | Use default credentials above |
| App won't launch | Build with `npm run electron:build:win` |
| Slow startup | Use `-SkipChecks` flag (advanced) |

### Log Locations

- **Backend logs**: Service windows (PowerShell)
- **Electron logs**: Electron DevTools console
- **Build logs**: Terminal where build command was run

---

## 🚀 Quick Command Reference

```powershell
# Start application (production)
.\START-COMPLETE-APP.ps1

# Start application (development)
.\START-COMPLETE-APP.ps1 -Development

# Start with verbose logging
.\START-COMPLETE-APP.ps1 -Verbose

# Stop all services
.\STOP-ALL-SERVICES.ps1

# Build for production
npm run electron:build:win

# Manual service start
cd backend
node mock-backend.js        # Port 8080
node auth-server.js         # Port 8082

# Check service health
Invoke-WebRequest http://localhost:8080/api/status
Invoke-WebRequest http://localhost:8082/api/auth/status

# View running services
Get-NetTCPConnection -LocalPort 8080,8082,3002 | Select-Object LocalPort,OwningProcess
```

---

## 📝 Version History

### Version 2026.01.08
- ✅ Initial complete startup system
- ✅ Comprehensive health checking
- ✅ Automatic port cleanup
- ✅ Dependency verification
- ✅ Development and production modes
- ✅ Service management scripts
- ✅ Detailed documentation

---

## 🎯 Summary

The complete startup system provides:

1. **Reliability**: Ensures all services start properly
2. **Automation**: No manual service management needed
3. **Health Checks**: Verifies each service is functioning
4. **Error Recovery**: Cleans up port conflicts automatically
5. **Flexibility**: Development and production modes
6. **Visibility**: Clear status reporting and logging
7. **Easy Management**: Simple start/stop commands

**To get started**: Just double-click `START-COMPLETE-APP.bat` or run `.\START-COMPLETE-APP.ps1 -Development`

---

*Nebula Shield Anti-Virus - Complete Startup System v2026.01.08*
