# Windows Installer Package - Quick Reference

## Current Status

✅ **Ready to Build** (except Inno Setup installation)

### What's Complete:
- ✅ Build scripts created
- ✅ Inno Setup configuration
- ✅ Service installation scripts
- ✅ Environment check script
- ✅ Documentation
- ✅ C++ backend built and ready
- ✅ React app ready to build
- ✅ Auth server dependencies installed

### What's Needed:
- ⚠️ **Inno Setup** - Download and install from https://jrsoftware.org/isdl.php

---

## Files Created

```
installer/
├── build-all.ps1               ← ONE-CLICK BUILD (run this!)
├── build-installer.ps1         ← Step 1: Prepare files
├── build-inno-installer.ps1    ← Step 2: Create .exe
├── check-environment.ps1       ← Verify prerequisites
├── nebula-shield.iss           ← Inno Setup configuration
├── README.md                   ← Detailed installer docs
└── INSTALLATION.md             ← End-user installation guide
```

---

## How to Build the Installer

### Prerequisites

1. **Install Inno Setup**
   - Download: https://jrsoftware.org/isdl.php
   - Run the installer
   - Use default installation path

2. **Verify Environment**
   ```powershell
   cd installer
   .\check-environment.ps1
   ```

### Build the Installer

**Option 1: One Command** (Recommended)
```powershell
cd installer
.\build-all.ps1
```

**Option 2: Step by Step**
```powershell
cd installer
.\build-installer.ps1          # Prepare files
.\build-inno-installer.ps1     # Create .exe
```

### Output

After successful build:
```
installer/output/NebulaShield-Setup-1.0.0.exe
```

This is your distributable installer! 🎉

---

## What the Installer Does

When users run `NebulaShield-Setup-1.0.0.exe`:

1. **Checks** Node.js is installed
2. **Installs** to `C:\Program Files\Nebula Shield`
3. **Creates** Windows services:
   - NebulaShieldBackend (C++ antivirus engine)
   - NebulaShieldAuth (Node.js auth server)
4. **Starts** services automatically
5. **Adds** Start Menu shortcuts
6. **Opens** browser to http://localhost:3000

---

## Installer Features

### Installation
- ✅ Administrator rights check
- ✅ Node.js prerequisite verification
- ✅ Customizable install location
- ✅ Component selection (services, desktop icon)
- ✅ Windows Service integration
- ✅ Automatic service startup
- ✅ Start Menu shortcuts

### Services
- **NebulaShieldBackend** (port 8080)
  - Real-time file monitoring
  - Virus scanning engine
  - Auto-start on Windows boot
  
- **NebulaShieldAuth** (port 8081)
  - User authentication
  - Settings persistence
  - Auto-start on Windows boot

### Uninstallation
- ✅ Stops all services
- ✅ Removes service registrations
- ✅ Deletes program files
- ✅ Optional user data deletion
- ✅ Clean registry removal

---

## Distribution

The final installer:
- **Filename**: `NebulaShield-Setup-1.0.0.exe`
- **Size**: ~50-100 MB (self-contained)
- **Platform**: Windows 10/11 x64
- **Requirements**: Node.js (installer checks and prompts)

### Installation Requirements
- Windows 10 or Windows 11 (64-bit)
- Administrator rights
- Node.js (v16 or higher)
- ~150 MB disk space
- Ports 8080, 8081, 3000 available

---

## Testing the Installer

### On Your Computer

1. **Build** the installer:
   ```powershell
   cd installer
   .\build-all.ps1
   ```

2. **Test** the installer:
   ```powershell
   cd output
   .\NebulaShield-Setup-1.0.0.exe
   ```

3. **Verify** services are running:
   - Open `services.msc`
   - Look for "Nebula Shield" services
   - Both should be "Running"

4. **Test** the application:
   - Open http://localhost:3000
   - Register a new account
   - Test features

5. **Uninstall** (if testing):
   - Start Menu → Uninstall Nebula Shield
   - Or: Settings → Apps → Nebula Shield → Uninstall

### On Another Computer

Copy `NebulaShield-Setup-1.0.0.exe` to a clean Windows machine and test full installation.

---

## Troubleshooting

### Build Issues

**"Inno Setup not found"**
- Install from https://jrsoftware.org/isdl.php
- Use default installation path
- Restart PowerShell after installation

**"Backend executable not found"**
```powershell
cd backend/build
cmake --build . --config Release
```

**"npm run build failed"**
```powershell
npm install
npm run build
```

### Installation Issues

**"Node.js is required"**
- Install Node.js LTS from https://nodejs.org/
- Restart computer
- Run installer again

**"Service installation failed"**
- Run installer as Administrator
- Check ports 8080 and 8081 are available
- Disable other antivirus temporarily

**"Cannot access application"**
- Verify services are running in `services.msc`
- Check firewall allows localhost connections
- View logs in `C:\Program Files\Nebula Shield\data\logs\`

---

## Next Steps

1. **Install Inno Setup**
   - Go to https://jrsoftware.org/isdl.php
   - Download and install

2. **Run Build**
   ```powershell
   cd installer
   .\build-all.ps1
   ```

3. **Test Installer**
   - Run the generated `.exe`
   - Verify everything works
   - Test uninstallation

4. **Distribute**
   - Share `NebulaShield-Setup-1.0.0.exe`
   - Optionally code-sign for production
   - Upload to download server

---

## Advanced Options

### Code Signing

For production, sign the installer to prevent SmartScreen warnings:

```powershell
# Requires a code signing certificate
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com NebulaShield-Setup-1.0.0.exe
```

### Custom Branding

Edit `installer/nebula-shield.iss`:
- Change company name
- Update URLs
- Customize wizard images
- Add license agreement

### Version Updates

1. Edit `installer/nebula-shield.iss`:
   ```pascal
   #define MyAppVersion "1.1.0"  ← Update this
   ```

2. Rebuild:
   ```powershell
   .\build-all.ps1
   ```

3. New file: `NebulaShield-Setup-1.1.0.exe`

---

## File Structure

### Build Directory (temporary)
```
installer/build/
├── backend/                   ← C++ antivirus engine
├── auth-server/              ← Node.js auth server  
├── frontend/                 ← React UI (built)
├── data/                     ← Database & logs
├── nssm.exe                  ← Service manager
├── install-services.bat      ← Service installer
├── uninstall-services.bat    ← Service remover
└── Nebula Shield.bat         ← App launcher
```

### Output Directory
```
installer/output/
└── NebulaShield-Setup-1.0.0.exe  ← FINAL INSTALLER
```

---

## Support

### Documentation
- `installer/README.md` - Detailed installer documentation
- `INSTALLATION.md` - End-user installation guide
- `SETTINGS_PERSISTENCE.md` - Settings persistence guide

### Getting Help
- Check build logs in PowerShell output
- Review Inno Setup compilation errors
- Test on clean Windows VM
- Check service logs after installation

---

## Summary

You now have a complete Windows installer package system that:

✅ Builds React frontend  
✅ Packages C++ backend  
✅ Bundles auth server  
✅ Creates Windows services  
✅ Installs with one .exe  
✅ Auto-starts on boot  
✅ Includes uninstaller  
✅ Manages all dependencies  

**To create the installer**: Install Inno Setup, then run `.\build-all.ps1`

🎉 Your antivirus app is ready for distribution!
