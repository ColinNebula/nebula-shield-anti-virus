# 🚀 Nebula Shield Anti-Virus - Startup Guide

## Quick Start Options

### Option 1: Simple Double-Click (Recommended)

#### For Web Development (React + Backend)
```
Double-click: START-ALL.bat
```
This will:
1. ✅ Check if backend is running, start if needed
2. ✅ Check if React is running, start if needed
3. ✅ Open both in separate windows
4. ✅ Automatically wait for servers to be ready

#### For Electron Desktop App
```
Double-click: START-ELECTRON.bat
```
This will:
1. ✅ Check if backend is running, start if needed
2. ✅ Launch Electron desktop application
3. ✅ Ensure backend is ready before opening app

---

### Option 2: NPM Commands

#### Start Everything (Backend + React)
```bash
npm run dev
# or
npm run start:all
```

#### Start Backend Only
```bash
npm run start:backend
```

#### Start React Only
```bash
npm start
```

#### Start Electron App
```bash
npm run electron:dev
```

---

### Option 3: PowerShell Scripts

#### Start All Servers
```powershell
.\start-app.ps1
```

#### Start Electron with Backend Check
```powershell
.\start-electron.ps1
```

---

## What Each Script Does

### 📝 START-ALL.bat
**Purpose:** Start both backend and React servers for web development

**Features:**
- ✅ Automatically detects if servers are already running
- ✅ Starts missing servers in separate windows
- ✅ Waits for servers to be fully ready
- ✅ Shows clear status messages
- ✅ Minimizes backend window to stay out of the way

**Use When:**
- Developing new features
- Testing in the browser
- Need hot module reloading

---

### 🖥️ START-ELECTRON.bat
**Purpose:** Launch the Electron desktop application

**Features:**
- ✅ Ensures backend is running first
- ✅ Starts backend automatically if not running
- ✅ Launches Electron only when backend is ready
- ✅ Proper error handling with clear messages

**Use When:**
- Testing the desktop app
- Want the native Windows application experience
- Building/testing Electron features

---

## Port Information

| Service | Port | URL |
|---------|------|-----|
| Backend API | 8080 | http://localhost:8080 |
| React Dev Server | 3001 | http://localhost:3001 |
| Electron App | - | Native Desktop App |

---

## Troubleshooting

### Problem: "Port already in use"

**Solution:**
1. The script automatically detects running servers
2. If you see this, it means the server is already running (good!)
3. The script will use the existing server

### Problem: "Failed to start backend"

**Possible Causes:**
1. Port 8080 is blocked by firewall
2. Another application is using port 8080
3. Node.js is not installed

**Solutions:**
```powershell
# Check what's using port 8080
netstat -ano | findstr :8080

# Kill process on port 8080 (if needed)
# Find PID from above command, then:
taskkill /PID <PID> /F

# Restart the script
.\START-ALL.bat
```

### Problem: "Backend takes too long to start"

**Solution:**
The script waits up to 30 seconds. If it still fails:
1. Check Node.js is installed: `node --version`
2. Check dependencies: `npm install`
3. Start backend manually: `npm run start:backend`

### Problem: "React won't start"

**Solution:**
```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install

# Try again
npm start
```

---

## Manual Startup (If Scripts Fail)

### Terminal 1 - Backend
```bash
cd Z:\Directory\projects\nebula-shield-anti-virus
node mock-backend-secure.js
```

### Terminal 2 - React
```bash
cd Z:\Directory\projects\nebula-shield-anti-virus
npm start
```

### Terminal 3 - Electron (Optional)
```bash
cd Z:\Directory\projects\nebula-shield-anti-virus
npm run electron
```

---

## Stopping Servers

### Stop Individual Windows
- Press `Ctrl+C` in each terminal window
- Close the terminal windows

### Stop All at Once
```powershell
# Stop all Node processes (nuclear option)
taskkill /F /IM node.exe
```

⚠️ **Warning:** This will stop ALL Node.js processes, not just Nebula Shield

---

## Development Workflow

### Recommended Setup

1. **Start servers once:**
   ```
   Double-click START-ALL.bat
   ```

2. **Keep servers running** while developing

3. **Make changes** to your code
   - React hot-reloads automatically
   - Backend requires restart for changes

4. **Restart backend only** when needed:
   ```bash
   # Stop current backend (Ctrl+C)
   # Start new instance
   npm run start:backend
   ```

---

## Build & Deploy

### Development Build
```bash
npm run build
```

### Production Build
```bash
npm run build:production
```

### Electron Distribution
```bash
# Windows installer
npm run electron:build:win

# Just build files (no installer)
npm run pack
```

---

## Environment Variables

### Backend Configuration
```env
PORT=8080                    # Backend port
NODE_ENV=development        # Environment
```

### React Configuration
```env
PORT=3001                   # React dev server port
REACT_APP_API_URL=http://localhost:8080
```

---

## Startup Script Features

### Automatic Checks ✅
- Port availability detection
- Server health verification
- Automatic recovery from failures
- Clear error messages

### Smart Behavior 🧠
- Reuses existing servers if running
- Waits for servers to be fully ready
- Opens windows in optimal positions
- Minimizes backend (stays out of way)

### Error Handling 🛡️
- Timeout protection (30s for backend, 60s for React)
- Clear error messages with solutions
- Graceful failure with helpful hints

---

## Quick Reference

| Task | Command/File |
|------|--------------|
| Start everything | `START-ALL.bat` |
| Start Electron | `START-ELECTRON.bat` |
| Backend only | `npm run start:backend` |
| React only | `npm start` |
| Check backend | http://localhost:8080/health |
| Check React | http://localhost:3001 |
| Stop all | `Ctrl+C` in each window |

---

## Advanced Options

### Custom Port
```bash
# Backend on different port
set PORT=9000 && node mock-backend-secure.js

# React on different port
set PORT=4000 && npm start
```

### Debug Mode
```bash
# Verbose backend logging
set DEBUG=* && npm run start:backend

# React with source maps
set GENERATE_SOURCEMAP=true && npm start
```

---

## Next Steps

After servers are running:

1. **Web App:** Visit http://localhost:3001
2. **Electron App:** Already launched if you used START-ELECTRON.bat
3. **API Documentation:** http://localhost:8080/health

---

## Support

If you encounter issues:

1. Check this guide first
2. Look at terminal output for errors
3. Try manual startup process
4. Check port availability
5. Restart your computer (last resort)

---

**Built with ❤️ for seamless development experience**

🛡️ Nebula Shield Anti-Virus - Protecting Your Digital Universe
