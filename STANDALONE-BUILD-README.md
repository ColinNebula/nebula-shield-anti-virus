# Nebula Shield Anti-Virus - Standalone Build Guide

## 🚀 Quick Start

### Build the Standalone Application

```powershell
# Run the standalone build script
.\build-standalone.ps1
```

The script will:
1. ✅ Install all dependencies
2. ✅ Build the React frontend with Vite
3. ✅ Prepare backend servers (Auth + Mock Backend)
4. ✅ Package everything with Electron
5. ✅ Create installer, portable, and ZIP versions

## 📦 What Gets Built

After running the build script, you'll find in the `dist/` folder:

### 1. **Installer (NSIS)**
- File: `Nebula Shield Anti-Virus-Setup-{version}.exe`
- Size: ~150-200 MB
- **Use when**: Installing on a single computer
- **Features**:
  - Full installation wizard
  - Start menu shortcuts
  - Desktop shortcut
  - Uninstaller included
  - Registry integration

### 2. **Portable Executable**
- File: `Nebula Shield Anti-Virus-Portable-{version}.exe`
- Size: ~150-200 MB  
- **Use when**: Running from USB drive or testing
- **Features**:
  - No installation required
  - Run from any location
  - All data stored locally
  - Perfect for testing

### 3. **ZIP Archive**
- File: `Nebula Shield Anti-Virus-{version}-win-x64.zip`
- Size: ~150-200 MB compressed
- **Use when**: Manual deployment needed
- **Features**:
  - Extract and run
  - Full control over location
  - All files accessible

## 🏗️ What's Included in the Build

### Frontend
- ✅ React 19 application (optimized with Vite)
- ✅ All UI components and pages
- ✅ Theme system (dark/light modes)
- ✅ Settings persistence (localStorage + backend)
- ✅ All assets and resources

### Backend Servers
- ✅ **Auth Server** (Port 8082)
  - User authentication
  - JWT token management
  - 2FA support
  - User settings storage
  - SQLite database

- ✅ **Mock Backend API** (Port 8080)
  - Scanning endpoints
  - Quarantine management
  - System status
  - Storage info
  - All API endpoints

### Data & Configuration
- ✅ SQLite databases (auto-created)
- ✅ Virus definitions
- ✅ Configuration files
- ✅ Default settings
- ✅ Quarantine storage
- ✅ Log directories

### Runtime
- ✅ Node.js runtime bundled
- ✅ All npm dependencies included
- ✅ Native modules (sqlite3) pre-compiled
- ✅ Electron framework

## 🖥️ Installation on Other Computer

### Method 1: Using Installer (Recommended)

1. **Copy the installer** to your test computer:
   ```
   dist/Nebula Shield Anti-Virus-Setup-{version}.exe
   ```

2. **Run the installer** (double-click)

3. **Follow the wizard**:
   - Choose installation directory
   - Select Start Menu folder
   - Create desktop shortcut (optional)

4. **Launch the application**:
   - From Start Menu: "Nebula Shield Anti-Virus"
   - From Desktop shortcut
   - Auto-starts on system boot (optional)

### Method 2: Using Portable Version (No Installation)

1. **Copy the portable executable**:
   ```
   dist/Nebula Shield Anti-Virus-Portable-{version}.exe
   ```

2. **Place it anywhere** (Desktop, USB drive, folder)

3. **Double-click to run** - No installation needed!

4. **Data storage**: All data saved next to the .exe file

### Method 3: Using ZIP Archive (Manual)

1. **Copy and extract the ZIP**:
   ```
   dist/Nebula Shield Anti-Virus-{version}-win-x64.zip
   ```

2. **Extract to desired location**

3. **Run the executable**:
   ```
   Nebula Shield Anti-Virus.exe
   ```

## 🧪 Testing the Standalone Build

### First Launch

1. **Double-click** to launch the application

2. **Wait for startup** (~5-10 seconds):
   - Backend servers initialize
   - Database connects
   - UI loads

3. **Login with test credentials**:
   ```
   Email: admin@test.com
   Password: admin
   ```

### Test Checklist

- [ ] **Dashboard**: Loads correctly, shows stats
- [ ] **Scanning**: Quick/Full scan buttons work
- [ ] **Settings**: Can change and save settings
- [ ] **Updates**: Signature update check works
- [ ] **Theme**: Switch between dark/light themes
- [ ] **Protection**: Real-time protection toggle
- [ ] **Quarantine**: View quarantined items
- [ ] **Firewall**: Configure firewall rules
- [ ] **Logs**: View activity logs
- [ ] **Profile**: User profile and subscription
- [ ] **Persistence**: Settings saved after restart

### Check Backend Servers

Open **DevTools** (View → Toggle Developer Tools):

```javascript
// Check if servers are responding
fetch('http://localhost:8080/api/status')
  .then(r => r.json())
  .then(console.log)

fetch('http://localhost:8082/api/auth/status')
  .then(r => r.json())
  .then(console.log)
```

Expected: Both should return `{ success: true, ... }`

## 🔍 Troubleshooting

### Application Won't Start

**Symptoms**: Double-clicking does nothing or crashes immediately

**Solutions**:
1. Check **Windows Defender** - may block the app
2. Run as **Administrator** (right-click → Run as Administrator)
3. Check **Firewall settings** - allow ports 8080 and 8082
4. Install **Visual C++ Redistributable** (if missing native modules)
5. Check **logs**: `%APPDATA%\Nebula Shield Anti-Virus\electron.log`

### Backend Servers Not Starting

**Symptoms**: App opens but shows errors about backend unavailable

**Solutions**:
1. **Ports in use**: Close apps using ports 8080 or 8082
2. **Permissions**: Run as Administrator
3. **Firewall**: Allow the application through firewall
4. Check logs: `%APPDATA%\Nebula Shield Anti-Virus\electron.log`

**Check ports**:
```powershell
netstat -ano | findstr ":8080"
netstat -ano | findstr ":8082"
```

### Settings Not Persisting

**Symptoms**: Settings reset after closing app

**Solutions**:
1. Check write permissions to `%APPDATA%` folder
2. Run as Administrator
3. Check if localStorage is working (open DevTools Console):
   ```javascript
   localStorage.setItem('test', 'works')
   localStorage.getItem('test') // Should return 'works'
   ```

### Database Errors

**Symptoms**: Login fails or "database locked" errors

**Solutions**:
1. Close any database viewers/editors
2. Delete and recreate database:
   ```
   %APPDATA%\Nebula Shield Anti-Virus\backend-data\data\auth.db
   ```
3. Restart the application

### Performance Issues

**Symptoms**: App is slow or unresponsive

**Solutions**:
1. Close unused applications
2. Disable real-time protection temporarily
3. Check Task Manager for CPU/Memory usage
4. Increase priority in Task Manager
5. Clear application cache:
   ```
   %APPDATA%\Nebula Shield Anti-Virus\Cache
   ```

## 📂 File Locations

### User Data
```
%APPDATA%\Nebula Shield Anti-Virus\
├── backend-data\          # Backend server data
│   ├── data\
│   │   ├── auth.db        # User database
│   │   ├── quarantine\    # Quarantined files
│   │   ├── logs\          # Application logs
│   │   └── backups\       # Database backups
├── storage\               # IndexedDB storage
├── Cache\                 # Application cache
└── electron.log           # Electron logs
```

### Installation (Installer Version)
```
C:\Program Files\Nebula Shield Anti-Virus\
├── Nebula Shield Anti-Virus.exe
├── resources\
│   ├── app.asar           # Application code
│   ├── backend\           # Backend servers
│   ├── data\              # Initial data
│   └── config\            # Configuration
└── Uninstall.exe
```

### Portable Version
```
[Your Location]\Nebula Shield Anti-Virus-Portable.exe
[Your Location]\backend-data\    # Created on first run
[Your Location]\storage\         # Created on first run
```

## 🔒 Security Notes

### Antivirus False Positives

Some antivirus software may flag the standalone build as suspicious because:
- It's unsigned (no code signing certificate)
- It bundles Node.js runtime
- It runs background servers
- It's a new/unknown executable

**Solutions**:
1. Add to antivirus **whitelist/exclusions**
2. Report as **false positive** to antivirus vendor
3. (Optional) Sign the executable with code signing certificate

### Firewall Permissions

The application requires these ports:
- **8080**: Mock Backend API (local only)
- **8082**: Auth Server (local only)
- **3003**: Local HTTP server for UI (local only)

All connections are **localhost only** - no external network access required.

### Data Privacy

- All data stored **locally** on your computer
- No telemetry or tracking
- No internet connection required
- User data encrypted in SQLite database

## 🛠️ Build Configuration

The build uses `electron-builder.standalone.json` which:
- Packages frontend (React build output)
- Bundles backend servers with dependencies
- Includes SQLite native modules
- Creates NSIS installer, portable, and ZIP
- Optimizes file size with compression
- Excludes development files and maps

## 📋 System Requirements

### Minimum
- **OS**: Windows 10 (64-bit) or later
- **RAM**: 2 GB
- **Disk**: 500 MB free space
- **CPU**: Dual-core 1.6 GHz

### Recommended
- **OS**: Windows 11 (64-bit)
- **RAM**: 4 GB or more
- **Disk**: 1 GB free space (for quarantine/logs)
- **CPU**: Quad-core 2.0 GHz or faster

## 🔄 Updating the Application

To update to a new version:

1. **Build new version**:
   ```powershell
   .\build-standalone.ps1
   ```

2. **Uninstall old version** (if using installer):
   - Settings → Apps → Uninstall

3. **Install new version**:
   - Run new installer
   - User data preserved automatically

**For portable version**: Just replace the .exe file

## 📞 Support

If you encounter issues:

1. **Check logs**:
   ```
   %APPDATA%\Nebula Shield Anti-Virus\electron.log
   ```

2. **Enable DevTools**:
   - Menu: View → Toggle Developer Tools
   - Check Console for errors

3. **Test backend health**:
   ```javascript
   // In DevTools Console
   fetch('http://localhost:8080/api/status')
   fetch('http://localhost:8082/api/auth/status')
   ```

4. **Report issues** with:
   - Error messages
   - Log files
   - Steps to reproduce
   - Windows version
   - Installation method

## ✅ Verification Checklist

Before distributing:

- [ ] Build completes without errors
- [ ] Installer runs on clean Windows system
- [ ] Portable version runs without installation
- [ ] Backend servers start automatically
- [ ] Database initializes correctly
- [ ] Login works (admin@test.com / admin)
- [ ] All features functional
- [ ] Settings persist after restart
- [ ] No console errors
- [ ] Adequate performance
- [ ] Firewall permissions prompt (if needed)
- [ ] Uninstaller works (installer version)

## 🎯 Distribution

### For Testing
- Use **Portable version** - easiest to distribute and test
- No installation required
- Copy single .exe file

### For Production
- Use **Installer version** - professional deployment
- Includes uninstaller
- Registry integration
- Start menu/desktop shortcuts

### For Archival
- Use **ZIP version** - backup and versioning
- Extract anywhere
- Manual control

---

## 📝 Quick Reference

```powershell
# Build standalone version
.\build-standalone.ps1

# Output location
cd dist

# Test locally (before distributing)
.\Nebula Shield Anti-Virus-Portable-{version}.exe

# Check backend logs
type "$env:APPDATA\Nebula Shield Anti-Virus\electron.log"

# Clean build
Remove-Item -Recurse -Force dist, build, node_modules
npm install
.\build-standalone.ps1
```

---

**Happy Testing! 🚀**
