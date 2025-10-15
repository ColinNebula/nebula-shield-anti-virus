# Nebula Shield Antivirus - Installation Guide

## Quick Install (For End Users)

1. **Download** the installer: `NebulaShield-Setup-1.0.0.exe`
2. **Run** the installer (requires administrator rights)
3. **Follow** the installation wizard
4. **Launch** Nebula Shield from Start Menu or Desktop
5. **Register** a free account to start using the antivirus

That's it! The services will start automatically.

---

## Building the Installer (For Developers)

### Prerequisites

Before building the installer, ensure you have:

1. ✅ **Node.js** (v16 or higher)
   - Download: https://nodejs.org/
   - Verify: `node --version`

2. ✅ **Visual Studio 2019/2022** with C++ tools
   - The C++ backend must already be built

3. ✅ **Inno Setup 6**
   - Download: https://jrsoftware.org/isdl.php
   - Install to default location

### Build Process

#### Option 1: One-Click Build (Recommended)

```powershell
cd installer
.\build-all.ps1
```

This automatically:
- ✅ Builds React frontend
- ✅ Copies C++ backend
- ✅ Packages auth server with dependencies
- ✅ Downloads NSSM service manager
- ✅ Creates service installation scripts
- ✅ Compiles Inno Setup installer

**Output**: `installer/output/NebulaShield-Setup-1.0.0.exe`

#### Option 2: Step-by-Step Build

**Step 1: Prepare Files**
```powershell
cd installer
.\build-installer.ps1
```

This will:
- Build React with `npm run build`
- Copy backend from `backend/build/bin/Release/`
- Install auth server production dependencies
- Download NSSM for Windows services
- Generate installation scripts

**Step 2: Create Installer**
```powershell
.\build-inno-installer.ps1
```

This will:
- Verify Inno Setup is installed
- Compile the `.iss` script
- Create the final `.exe` installer

### Build Requirements

Before running the build scripts, ensure:

1. **C++ Backend is Built**
   ```bash
   cd backend
   mkdir build
   cd build
   cmake .. -G "Visual Studio 16 2019"
   cmake --build . --config Release
   ```

2. **React Dependencies Installed**
   ```bash
   npm install
   ```

3. **Auth Server Dependencies Installed**
   ```bash
   cd backend
   npm install
   ```

### What Gets Packaged

The installer includes:

```
Nebula Shield/
├── backend/
│   ├── nebula_shield_backend.exe    ← C++ antivirus engine
│   ├── sqlite3.dll                   ← Database library
│   ├── libcrypto-3-x64.dll           ← Crypto library
│   └── signatures.db                 ← Virus signatures
│
├── auth-server/
│   ├── auth-server.js                ← Node.js auth server
│   ├── package.json
│   └── node_modules/                 ← Production dependencies only
│
├── frontend/
│   └── [React build output]          ← Optimized static files
│
├── data/
│   ├── logs/                         ← Application logs
│   ├── quarantine/                   ← Quarantined files
│   └── signatures.db                 ← Threat database
│
├── nssm.exe                          ← Service manager
├── install-services.bat              ← Service installer
├── uninstall-services.bat            ← Service uninstaller
└── Nebula Shield.bat                 ← Application launcher
```

---

## Installation Process (User Experience)

### 1. Welcome Screen
- Displays product name and version
- Shows license agreement
- Requires acceptance to continue

### 2. Prerequisite Check
- Verifies Node.js installation
- If not found, offers to open download page
- Installation cannot proceed without Node.js

### 3. Choose Install Location
- Default: `C:\Program Files\Nebula Shield`
- User can change directory
- Requires ~150 MB free space

### 4. Select Components
- ✅ **Install and start services** (recommended)
  - Installs Windows services
  - Configures auto-start on boot
- ☐ Create desktop icon (optional)

### 5. Installation
- Copies all files to destination
- Installs NSSM service manager
- Registers Windows services
- Creates Start Menu shortcuts

### 6. Service Installation
If "Install services" was selected:
- Installs **NebulaShieldBackend** service
- Installs **NebulaShieldAuth** service
- Starts both services
- Configures automatic startup

### 7. Completion
- Shows success message
- Option to launch application
- Opens browser to http://localhost:3000

---

## What Gets Installed

### Windows Services

**NebulaShieldBackend**
- **Display Name**: Nebula Shield Antivirus Backend
- **Description**: Real-time antivirus protection engine
- **Executable**: `nebula_shield_backend.exe`
- **Port**: 8080
- **Startup Type**: Automatic
- **Logs**: `data/logs/backend-service.log`

**NebulaShieldAuth**
- **Display Name**: Nebula Shield Auth Server
- **Description**: User authentication and settings management
- **Executable**: `node.exe auth-server/auth-server.js`
- **Port**: 8081
- **Startup Type**: Automatic
- **Logs**: `data/logs/auth-service.log`

### Start Menu Items
- **Nebula Shield Antivirus** - Launch application
- **Uninstall Nebula Shield** - Remove application

### Registry Entries
- Uninstall information in `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`
- Application GUID: `{B9C8F5D3-4A2E-4B7C-9F1A-3D8E6C5B4A2F}`

---

## Service Management

### Using Windows Services

1. Press `Win + R`
2. Type `services.msc`
3. Find "Nebula Shield" services
4. Right-click to Start/Stop/Restart

### Using Command Line

**Start Services:**
```cmd
net start NebulaShieldBackend
net start NebulaShieldAuth
```

**Stop Services:**
```cmd
net stop NebulaShieldBackend
net stop NebulaShieldAuth
```

**Check Status:**
```cmd
sc query NebulaShieldBackend
sc query NebulaShieldAuth
```

### Using NSSM

```cmd
cd "C:\Program Files\Nebula Shield"

# Start services
nssm start NebulaShieldBackend
nssm start NebulaShieldAuth

# Stop services
nssm stop NebulaShieldBackend
nssm stop NebulaShieldAuth

# Restart services
nssm restart NebulaShieldBackend
nssm restart NebulaShieldAuth

# View status
nssm status NebulaShieldBackend
```

---

## Uninstallation

### Standard Uninstall

1. **Start Menu** → Right-click "Nebula Shield" → Uninstall
2. Or: **Settings** → Apps → Nebula Shield → Uninstall
3. Follow the uninstall wizard

### What Gets Removed

Automatically removed:
- ✅ All program files
- ✅ Windows services
- ✅ Start Menu shortcuts
- ✅ Desktop shortcuts (if created)
- ✅ Registry entries

Optional removal (user choice):
- ☐ User data (quarantine, logs, settings)
- ☐ Database files

### Manual Cleanup (if needed)

If uninstaller fails or you need to remove manually:

```cmd
# Stop services
net stop NebulaShieldBackend
net stop NebulaShieldAuth

# Remove services
sc delete NebulaShieldBackend
sc delete NebulaShieldAuth

# Delete files
rmdir /s /q "C:\Program Files\Nebula Shield"
```

---

## Troubleshooting

### Installation Issues

**Error: "Node.js is required"**
- Install Node.js from https://nodejs.org/
- Use LTS version (v18 or higher recommended)
- Restart computer after installation

**Error: "Installation failed"**
- Run installer as Administrator
- Disable antivirus temporarily
- Check disk space (need ~150 MB)

**Error: "Service installation failed"**
- Ensure ports 8080 and 8081 are available
- Check Windows Services are accessible
- Run `install-services.bat` manually as Admin

### Runtime Issues

**Services won't start**
```cmd
# Check if ports are in use
netstat -ano | findstr :8080
netstat -ano | findstr :8081

# View service logs
type "C:\Program Files\Nebula Shield\data\logs\backend-service.log"
type "C:\Program Files\Nebula Shield\data\logs\auth-service.log"
```

**Can't access UI (localhost:3000)**
- Services must be running first
- Check firewall isn't blocking localhost
- Try http://127.0.0.1:3000 instead

**Real-time protection not working**
- Ensure backend service is running
- Check logs for errors
- Verify permissions (service runs as SYSTEM)

### Getting Help

1. **Check Logs**:
   - Backend: `data/logs/backend-service.log`
   - Auth: `data/logs/auth-service.log`
   - Quarantine: `data/logs/quarantine.log`

2. **Verify Services**:
   ```cmd
   sc query NebulaShieldBackend
   sc query NebulaShieldAuth
   ```

3. **Test Connectivity**:
   ```powershell
   curl http://localhost:8080/api/status
   curl http://localhost:8081/api/health
   ```

---

## Advanced Configuration

### Change Service Ports

Edit configuration before rebuilding:

**Backend (C++)**: `backend/build/bin/config.json`
```json
{
  "server_port": 8080  ← Change this
}
```

**Auth Server**: `backend/.env`
```
PORT=8081  ← Change this
```

### Custom Install Location

Edit `installer/nebula-shield.iss`:
```pascal
DefaultDirName={autopf}\Nebula Shield  ← Change this
```

### Disable Auto-Start

After installation:
```cmd
sc config NebulaShieldBackend start= demand
sc config NebulaShieldAuth start= demand
```

---

## Distribution

The final installer (`NebulaShield-Setup-1.0.0.exe`) is:
- ✅ Self-contained
- ✅ Digitally unsigned (consider code signing for production)
- ✅ ~50-100 MB in size
- ✅ Windows 10/11 x64 compatible

### Code Signing (Recommended)

For production distribution, sign the installer:

```powershell
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com NebulaShield-Setup-1.0.0.exe
```

This prevents Windows SmartScreen warnings.

---

## Version Updates

To create a new version:

1. Update version in `installer/nebula-shield.iss`:
   ```pascal
   #define MyAppVersion "1.1.0"
   ```

2. Rebuild the installer:
   ```powershell
   .\build-all.ps1
   ```

3. New installer: `NebulaShield-Setup-1.1.0.exe`

---

## Security Considerations

- Services run as **Local System** account
- Requires **Administrator** rights to install
- May trigger **SmartScreen** (unsigned executable)
- May be flagged by other **antiviruses** (false positive)
- User data stored in **Program Files** (protected location)

---

## Support

For issues or questions:
- Check the logs in `data/logs/`
- Review this installation guide
- See main `README.md` for application usage
- Report issues on GitHub (if applicable)
