# 🚀 Nebula Shield - Standalone Build Quick Start

## ⚡ TL;DR - Quick Build

```powershell
# Option 1: Double-click this file
BUILD-STANDALONE.bat

# Option 2: Run PowerShell command
npm run build:standalone

# Option 3: Direct PowerShell
.\build-standalone.ps1
```

**Output**: `dist/` folder with installer, portable, and ZIP versions

---

## 📦 What You Get

After building, you'll have 3 distributable versions in the `dist/` folder:

| Type | File | Size | Use Case |
|------|------|------|----------|
| **Installer** | `Nebula Shield Anti-Virus-Setup-{version}.exe` | ~150-200 MB | Full installation on Windows |
| **Portable** | `Nebula Shield Anti-Virus-Portable-{version}.exe` | ~150-200 MB | No installation needed, run anywhere |
| **ZIP** | `Nebula Shield Anti-Virus-{version}-win-x64.zip` | ~150-200 MB | Manual extraction and deployment |

---

## ✅ Quick Build Steps

### 1. Verify You're Ready
```powershell
.\verify-build-ready.ps1
```

This checks:
- Node.js and npm installed
- Required files present
- Dependencies ready
- Disk space available

### 2. Build the Application
```powershell
.\BUILD-STANDALONE.bat
```

This will:
1. Install all dependencies
2. Build React frontend with Vite
3. Prepare backend servers
4. Package with Electron
5. Create installer, portable, and ZIP versions

**Time**: 5-10 minutes (first build), 2-5 minutes (subsequent)

### 3. Test Locally (Optional but Recommended)
```powershell
.\test-built-app.ps1
```

This lets you:
- Choose which version to test
- Launch the application
- Verify backend servers start
- Check for errors

### 4. Transfer to Other Computer

**Copy one of these files:**
- `dist/Nebula Shield Anti-Virus-Portable-{version}.exe` ← Easiest for testing
- `dist/Nebula Shield Anti-Virus-Setup-{version}.exe` ← For proper installation
- `dist/Nebula Shield Anti-Virus-{version}-win-x64.zip` ← For manual deployment

---

## 🧪 Testing on Other Computer

### Quick Test (Portable Version)

1. **Copy portable .exe** to other computer
2. **Double-click** to run
3. **Wait 5-10 seconds** for startup
4. **Login**:
   - Email: `admin@test.com`
   - Password: `admin`
5. **Test features**:
   - Dashboard loads
   - Settings work
   - Theme toggle
   - Scan buttons respond

### Installation Test (Installer Version)

1. **Run installer** on other computer
2. **Follow wizard** to install
3. **Launch** from Start Menu
4. **Login** and test (same as above)
5. **Verify persistence** - settings save after restart

---

## 🛠️ Troubleshooting

### Application Won't Start

```powershell
# Check if ports are available
netstat -ano | findstr ":8080"
netstat -ano | findstr ":8082"

# Kill processes using these ports
taskkill /F /PID <PID>

# Run as Administrator
```

### Backend Servers Not Starting

1. Check logs: `%APPDATA%\Nebula Shield Anti-Virus\electron.log`
2. Allow through Firewall
3. Run as Administrator
4. Check antivirus isn't blocking

### Settings Not Saving

1. Check write permissions to `%APPDATA%`
2. Run as Administrator
3. Check localStorage in DevTools:
   ```javascript
   localStorage.setItem('test', 'works')
   localStorage.getItem('test')
   ```

---

## 📁 What's Included in the Build

### Frontend (React + Vite)
- ✅ All UI components
- ✅ Dashboard, Settings, Scanning pages
- ✅ Theme system (dark/light)
- ✅ All assets and images

### Backend Servers
- ✅ **Auth Server** (Port 8082)
  - User authentication
  - JWT tokens
  - 2FA support
  - User settings
  
- ✅ **Mock Backend** (Port 8080)
  - Scanning API
  - Quarantine management
  - System status
  - All features

### Data & Runtime
- ✅ SQLite database (auto-created)
- ✅ Node.js runtime bundled
- ✅ All npm dependencies
- ✅ Native modules (sqlite3)
- ✅ Configuration files

---

## 🔒 Security & Permissions

### Required Permissions

The app needs these **local-only** ports:
- **8080** - Mock Backend API
- **8082** - Auth Server
- **3003** - UI Local Server

**No internet connection required** - everything runs locally!

### Firewall Prompt

Windows Firewall may ask for permission on first run:
- ✅ **Allow** on Private networks
- ❌ **Block** on Public networks (not needed)

### Antivirus False Positives

Some antivirus may flag the app because:
- Unsigned executable (no code signing cert)
- Bundles Node.js runtime
- Runs background servers

**Solution**: Add to antivirus whitelist/exclusions

---

## 📊 Performance Notes

### System Requirements

| | Minimum | Recommended |
|---|---|---|
| **OS** | Windows 10 x64 | Windows 11 x64 |
| **RAM** | 2 GB | 4 GB+ |
| **Disk** | 500 MB | 1 GB+ |
| **CPU** | Dual-core 1.6 GHz | Quad-core 2.0 GHz+ |

### Startup Time

- First launch: 5-10 seconds
- Subsequent launches: 3-5 seconds
- Backend initialization: 2-3 seconds

---

## 🔄 Updates & Rebuilding

To create a new version:

```powershell
# Clean previous build
Remove-Item -Recurse -Force dist, build

# Rebuild
.\BUILD-STANDALONE.bat
```

User data is preserved in:
```
%APPDATA%\Nebula Shield Anti-Virus\
```

---

## 📞 Support & Debugging

### View Logs

```powershell
# Open log file
notepad "$env:APPDATA\Nebula Shield Anti-Virus\electron.log"

# Or in PowerShell
type "$env:APPDATA\Nebula Shield Anti-Virus\electron.log"
```

### Check Backend Health

In the app, open DevTools (F12 or View → Toggle Developer Tools):

```javascript
// Check Mock Backend
fetch('http://localhost:8080/api/status')
  .then(r => r.json())
  .then(console.log)

// Check Auth Server  
fetch('http://localhost:8082/api/auth/status')
  .then(r => r.json())
  .then(console.log)
```

### Clear App Data

```powershell
# Close app first, then:
Remove-Item -Recurse -Force "$env:APPDATA\Nebula Shield Anti-Virus"
```

---

## 📝 Checklist for Distribution

Before giving to others:

- [ ] Built successfully without errors
- [ ] Tested locally - app starts
- [ ] Backend servers running
- [ ] Can login (admin@test.com / admin)
- [ ] Dashboard loads
- [ ] Settings persist after restart
- [ ] No console errors in DevTools
- [ ] Tested on clean Windows system (if possible)

---

## 🎯 Common Use Cases

### For Quick Testing
```powershell
# Build and test
.\BUILD-STANDALONE.bat
.\test-built-app.ps1
# Select Portable version
```

### For Installation Testing
```powershell
# Build
.\BUILD-STANDALONE.bat

# Copy installer to other PC
copy "dist\*Setup*.exe" "D:\USB Drive\"

# On other PC: Run installer
```

### For Development Testing
```powershell
# Don't build - run in dev mode
npm run electron:dev
```

---

## 🚀 Quick Commands Reference

```powershell
# Verify readiness
.\verify-build-ready.ps1

# Build standalone
.\BUILD-STANDALONE.bat
# or
npm run build:standalone

# Test built app
.\test-built-app.ps1

# Check backend health
netstat -ano | findstr ":8080"
netstat -ano | findstr ":8082"

# View logs
type "$env:APPDATA\Nebula Shield Anti-Virus\electron.log"

# Clean build
Remove-Item -Recurse -Force dist, build
npm install
.\BUILD-STANDALONE.bat
```

---

## 📖 Full Documentation

For complete details, see:
- **[STANDALONE-BUILD-README.md](./STANDALONE-BUILD-README.md)** - Comprehensive guide
- **[ADMIN_PANEL_GUIDE.md](./ADMIN_PANEL_GUIDE.md)** - Admin features
- **[ADVANCED_FEATURES.md](./ADVANCED_FEATURES.md)** - All features explained

---

## ✨ That's It!

You now have a fully functional standalone version of Nebula Shield that:
- ✅ Runs on any Windows computer
- ✅ Includes frontend + backend
- ✅ Works offline
- ✅ All features functional
- ✅ Settings persist
- ✅ No manual server startup needed

**Happy Testing! 🎉**
