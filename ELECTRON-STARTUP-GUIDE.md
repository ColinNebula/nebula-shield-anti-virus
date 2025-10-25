# 🚀 Nebula Shield Anti-Virus - Quick Start Guide

## Running the Application

### Option 1: Production Electron App (Recommended)

**Prerequisites:**
- Node.js installed
- Application already built

**Steps:**
1. Double-click `START-ELECTRON-APP.bat`
2. The backend will start automatically
3. The Electron app will launch

**Or manually:**
```batch
# Start backend
cd backend
node mock-backend.js

# In another terminal, run the app
dist\win-unpacked\Nebula Shield Anti-Virus.exe
```

---

### Option 2: Development Mode with Hot Reload

**For active development:**

1. Double-click `START-ELECTRON-DEV-COMPLETE.bat`

**Or manually:**
```batch
# Terminal 1: Start backend
cd backend
node mock-backend.js

# Terminal 2: Start Vite dev server
npm run dev

# Terminal 3: Start Electron (will connect to Vite)
set ELECTRON_START_URL=http://localhost:3002
npm run electron:dev
```

---

### Option 3: Web Browser Mode (Development)

**For testing in a browser:**

1. Start backend:
   ```batch
   cd backend
   node mock-backend.js
   ```

2. Start Vite dev server:
   ```batch
   npm run dev
   ```

3. Open browser to `http://localhost:3002`

---

## Building the Application

### Build Electron App for Windows:

```batch
# Option 1: Use batch file
BUILD-ELECTRON-WIN.bat

# Option 2: Use npm script
npm run electron:build:win
```

**Output:**
- `dist/win-unpacked/Nebula Shield Anti-Virus.exe` - Portable executable
- `dist/Nebula Shield Anti-Virus Setup 0.1.0.exe` - Installer

---

## Default Login Credentials

**Admin Account (created by mock-backend.js):**
- Email: `admin@test.com`
- Password: `admin`

**Database Admin (from auth-server.js):**
- Email: `admin@nebulashield.com`
- Password: `Nebula2025!`

---

## Port Configuration

| Service | Port | Description |
|---------|------|-------------|
| **Backend API** | 8080 | Unified backend (auth + antivirus API) |
| **Vite Dev Server** | 3002 | Frontend development server with hot reload |
| **Electron App** | N/A | Uses backend on 8080 (production) or Vite on 3002 (dev) |

---

## Important Notes

### ⚠️ Backend Servers - Use ONE Only!

There are TWO backend files:
1. **`backend/mock-backend.js`** ✅ **USE THIS** - Complete unified backend
2. **`backend/auth-server.js`** ❌ Don't use with mock-backend

**Never run both at the same time!** They both try to use port 8080.

The `mock-backend.js` includes:
- ✅ Authentication endpoints
- ✅ Antivirus API endpoints
- ✅ All features

### 🔧 Troubleshooting

**"Application failed to load":**
- Ensure backend is running on port 8080
- Check no other process is using port 8080:
  ```batch
  netstat -ano | findstr :8080
  ```

**"Network Error" in login:**
- Backend is not running
- Start backend with: `cd backend && node mock-backend.js`

**Multiple Electron instances running:**
```batch
# Stop all instances
taskkill /F /IM "Nebula Shield Anti-Virus.exe"
```

**Port already in use:**
```batch
# Find process using port 8080
netstat -ano | findstr :8080

# Kill process (replace PID with actual process ID)
taskkill /F /PID <PID>
```

### 📦 File Structure

```
nebula-shield-anti-virus/
├── backend/
│   ├── mock-backend.js         ← Main backend (USE THIS)
│   ├── auth-server.js          ← Standalone auth (don't use with mock-backend)
│   └── ...
├── dist/
│   ├── win-unpacked/
│   │   └── Nebula Shield Anti-Virus.exe  ← Portable app
│   └── Nebula Shield Anti-Virus Setup 0.1.0.exe  ← Installer
├── public/
│   ├── electron.js             ← Main Electron process
│   └── preload.js              ← Preload script
├── src/                        ← React frontend source
├── START-ELECTRON-APP.bat      ← Launch production app
├── START-ELECTRON-DEV-COMPLETE.bat  ← Launch dev environment
└── BUILD-ELECTRON-WIN.bat      ← Build Electron app
```

---

## Development Workflow

1. **Make frontend changes** → Saved automatically with hot reload in dev mode
2. **Make backend changes** → Restart backend server
3. **Make Electron changes** → Restart Electron app
4. **Build for production** → Run `BUILD-ELECTRON-WIN.bat`

---

## Next Steps

- **First time setup**: Run `npm install` in root directory
- **Backend dependencies**: Run `npm install` in `backend/` directory
- **Start developing**: Use `START-ELECTRON-DEV-COMPLETE.bat`
- **Build for release**: Use `BUILD-ELECTRON-WIN.bat`

---

## Support

For issues or questions:
- Check the error logs in: `%APPDATA%/nebula-shield-anti-virus/electron.log`
- Review backend console output
- Check browser/Electron DevTools console
