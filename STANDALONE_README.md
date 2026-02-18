# Nebula Shield Anti-Virus - Standalone Installation

## System Requirements

### Required Software

**IMPORTANT**: Nebula Shield requires **Node.js** to be installed on the target computer.

- **Operating System**: Windows 10/11 (64-bit)
- **Node.js**: Version 18.x or higher (REQUIRED)
- **RAM**: 4GB minimum (8GB recommended)
- **Disk Space**: 500MB free space
- **Privileges**: Administrator rights for NSIS installer

### Installing Node.js

If Node.js is not installed, download and install it from:
**https://nodejs.org/**

1. Download the **LTS (Long Term Support)** version
2. Run the installer
3. Follow the installation wizard
4. Restart your computer after installation
5. Verify installation by opening Command Prompt and typing: `node --version`

## Installation Methods

### Method 1: NSIS Installer (Recommended)

**File**: `Nebula Shield Anti-Virus-0.1.0-x64.exe`

1. Ensure Node.js is installed (see above)
2. Double-click the installer
3. Follow the installation wizard
4. Choose installation directory
5. Select shortcut options
6. Click "Install"
7. Launch the application

**Features**:
- Professional installation wizard
- Automatic file associations
- Desktop & Start Menu shortcuts
- Clean uninstallation
- Preserves user data on uninstall

### Method 2: Portable Version

**File**: `Nebula Shield Anti-Virus-0.1.0-x64-portable.exe`

1. Ensure Node.js is installed (see above)
2. Copy the portable executable to any location
3. Double-click to run
4. No installation required

**Features**:
- No installation needed
- Run from USB drive
- Perfect for testing
- No administrator rights needed (except for Node.js)

## First Run

### What Happens on First Launch

1. **Backend Initialization**: The application starts an internal backend server on port 8080
2. **Data Directory Creation**: Creates necessary folders in `%APPDATA%\Nebula Shield Anti-Virus`
3. **Database Setup**: Initializes the security database
4. **Signature Updates**: Downloads initial virus signatures (requires internet)

### Data Locations

**Application Data**: `%APPDATA%\Nebula Shield Anti-Virus\`
- Settings and preferences
- Virus signature database
- Scan history and logs
- Quarantined files
- User authentication data

**Backend Data**: `%APPDATA%\Nebula Shield Anti-Virus\backend-data\`
- Backend server logs
- Temporary scan files
- Real-time protection cache

## Troubleshooting

### Backend Not Starting

**Error**: "Backend server is not responding"

**Solutions**:
1. **Check Node.js Installation**:
   - Open Command Prompt
   - Type: `node --version`
   - Should display version number (e.g., v18.12.0)
   - If not found, install Node.js

2. **Check Port 8080**:
   - Port 8080 must be available
   - Close other applications using this port
   - Or restart your computer

3. **Firewall Settings**:
   - Allow Nebula Shield through Windows Firewall
   - Go to: Settings → Update & Security → Windows Security → Firewall & Network Protection
   - Click "Allow an app through firewall"
   - Find and check "Nebula Shield Anti-Virus"

4. **Antivirus Conflicts**:
   - Some antivirus software may block the backend
   - Temporarily disable other security software during first run
   - Add Nebula Shield to your antivirus whitelist

5. **Run as Administrator**:
   - Right-click the application
   - Select "Run as administrator"

### Application Won't Launch

**Problem**: Nothing happens when clicking the installer/executable

**Solutions**:
1. Check Windows SmartScreen:
   - Click "More info"
   - Click "Run anyway"

2. Verify system requirements:
   - 64-bit Windows 10 or 11
   - Sufficient disk space
   - Administrator privileges

3. Check Event Viewer:
   - Open Event Viewer (eventvwr.msc)
   - Look for application errors
   - Note the error details

### Log Files

If you experience issues, check the log files:

**Main Application Log**:
`%APPDATA%\Nebula Shield Anti-Virus\electron.log`

**Backend Log**:
`%APPDATA%\Nebula Shield Anti-Virus\backend-data\data\logs\`

These logs contain detailed information about:
- Startup sequence
- Backend initialization
- Error messages
- System paths

## Manual Backend Test

If the backend isn't starting automatically, you can test it manually:

### Windows Command Prompt

```cmd
cd "C:\Program Files\Nebula Shield Anti-Virus\resources\backend"
node auth-server.js
```

### Expected Output

```
[Timestamp] Starting Nebula Shield Backend Server...
[Timestamp] Database initialized
[Timestamp] Server listening on port 8080
```

If you see errors, they will indicate what's wrong (missing dependencies, port in use, etc.)

## Uninstallation

### NSIS Installer Version

1. Open "Apps & Features" (Settings → Apps)
2. Find "Nebula Shield Anti-Virus"
3. Click "Uninstall"
4. Follow the uninstaller wizard
5. Choose whether to keep user data

### Portable Version

1. Simply delete the portable executable
2. Optionally delete data folder: `%APPDATA%\Nebula Shield Anti-Virus`

## Distribution Notes

### For System Administrators

**Silent Installation** (NSIS only):
```cmd
"Nebula Shield Anti-Virus-0.1.0-x64.exe" /S
```

**Custom Install Location**:
```cmd
"Nebula Shield Anti-Virus-0.1.0-x64.exe" /D=C:\CustomPath
```

**Prerequisites**:
- Ensure Node.js is installed on all target machines
- Open port 8080 for localhost communication
- Allow application through enterprise firewall

### Network Deployment

1. Install Node.js via Group Policy or SCCM
2. Deploy Nebula Shield using your software distribution tool
3. Configure firewall rules to allow localhost:8080
4. Pre-configure settings via registry or config files

## Support

### Getting Help

**Check Logs First**: Most issues can be diagnosed from log files

**Common Issues**:
1. Node.js not installed → Install from nodejs.org
2. Port 8080 in use → Close conflicting applications
3. Firewall blocking → Allow through Windows Firewall
4. Antivirus interference → Add to whitelist

### Contact Information

- **Email**: support@nebulashield.com
- **Documentation**: https://github.com/nebula-shield/docs
- **Issues**: https://github.com/nebula-shield/issues

## Version Information

- **Version**: 0.1.0
- **Build Date**: November 2025
- **Platform**: Windows 10/11 (x64)
- **Node.js Required**: 18.x or higher

---

**Remember**: Node.js must be installed before running Nebula Shield Anti-Virus!
