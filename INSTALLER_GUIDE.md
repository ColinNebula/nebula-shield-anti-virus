# Nebula Shield Anti-Virus - Installer Package Guide

## Overview

This guide explains how to build installer packages for Nebula Shield Anti-Virus so you can install the application on other computers.

## Quick Start

### Building the Installer

**Option 1: Using PowerShell Script (Recommended)**
```powershell
npm run build:installer
```

**Option 2: Using npm directly**
```bash
npm run electron:build:win
```

**Option 3: Using the PowerShell script directly**
```powershell
powershell -ExecutionPolicy Bypass -File ./build-installer.ps1
```

## What Gets Created

The build process creates **TWO** installer types in the `dist` folder:

### 1. NSIS Installer (.exe)
- **File**: `Nebula Shield Anti-Virus-0.1.0-x64.exe`
- **Type**: Full-featured Windows installer
- **Features**:
  - Professional installation wizard
  - Choose installation directory
  - Create desktop & start menu shortcuts
  - Automatic uninstaller
  - Preserves user data on uninstall (optional)
  - Requires administrator privileges
- **Best For**: Standard installations on client computers

### 2. Portable Version (.exe)
- **File**: `Nebula Shield Anti-Virus-0.1.0-x64-portable.exe`
- **Type**: Standalone executable
- **Features**:
  - No installation required
  - Run directly from any location
  - Perfect for USB drives or temporary use
  - No administrator rights needed
- **Best For**: Testing, temporary use, or restricted environments

## Installation Process

### Installing on Another Computer

#### Method 1: NSIS Installer (Recommended)

1. **Copy the installer** to the target computer:
   - File: `dist/Nebula Shield Anti-Virus-0.1.0-x64.exe`

2. **Run the installer**:
   - Double-click the installer file
   - Follow the installation wizard
   - Choose installation directory (default: `C:\Program Files\Nebula Shield Anti-Virus`)
   - Select shortcut options
   - Click "Install"

3. **Launch the application**:
   - Use desktop shortcut, or
   - Use Start Menu shortcut, or
   - Navigate to installation directory

4. **First Run**:
   - The application will create necessary data directories
   - Backend server will start automatically
   - Initial configuration will be performed

#### Method 2: Portable Version

1. **Copy the portable executable** to the target computer:
   - File: `dist/Nebula Shield Anti-Virus-0.1.0-x64-portable.exe`

2. **Run directly**:
   - Double-click the executable
   - No installation required
   - Data stored in the same folder

## System Requirements

### Development/Build System
- Node.js 18.x or higher
- npm 9.x or higher
- Windows 10/11 (for building Windows installers)
- At least 2GB free disk space for build process
- Internet connection for dependencies

### Target/Installation System
- Windows 10 or Windows 11 (64-bit)
- 4GB RAM minimum (8GB recommended)
- 500MB free disk space
- Administrator privileges (for NSIS installer)

## Build Configuration

### Electron Builder Configuration
The installer is configured via `electron-builder.json`:

```json
{
  "appId": "com.nebulashield.antivirus",
  "productName": "Nebula Shield Anti-Virus",
  "win": {
    "target": ["nsis", "portable"],
    "requestedExecutionLevel": "requireAdministrator"
  },
  "nsis": {
    "oneClick": false,
    "allowToChangeInstallationDirectory": true,
    "createDesktopShortcut": true,
    "createStartMenuShortcut": true
  }
}
```

### What's Included in the Installer

The installer packages include:

1. **Application Files**:
   - Built React application (`build/` folder)
   - Electron main process (`public/electron.js`)
   - Application icons and resources

2. **Backend Components**:
   - Authentication server
   - Database files
   - API endpoints

3. **Data Directories**:
   - Signature databases
   - Quarantine folder
   - Logs folder
   - Settings and configuration

4. **Resources**:
   - Application icons
   - License information

## Advanced Options

### Building Without Checks

If you want to skip the pre-build checks:

```bash
npm run build
electron-builder --win
```

### Building Only NSIS Installer

```bash
electron-builder --win nsis
```

### Building Only Portable

```bash
electron-builder --win portable
```

### Debug Build

```bash
electron-builder --win --config.compression=store
```

## Customization

### Changing Version Number

Edit `package.json`:
```json
{
  "version": "0.1.0"  // Change this
}
```

### Customizing Installer Appearance

Edit `build-resources/installer.nsh` for custom NSIS scripts.

### Application Icon

Replace `build-resources/icon.ico` with your custom icon.

## Troubleshooting

### Build Fails

**Problem**: `npm run build:installer` fails

**Solutions**:
1. Ensure all dependencies are installed:
   ```bash
   npm install
   ```

2. Clean previous builds:
   ```bash
   Remove-Item -Recurse -Force dist, build
   ```

3. Check Node.js version:
   ```bash
   node --version  # Should be 18.x or higher
   ```

### Installer Doesn't Run on Target Computer

**Problem**: Double-clicking installer does nothing

**Solutions**:
1. Check Windows SmartScreen - click "More info" → "Run anyway"
2. Verify target computer is 64-bit Windows
3. Run as Administrator (right-click → "Run as administrator")

### Application Won't Start After Installation

**Problem**: Installed app doesn't launch

**Solutions**:
1. Check if required ports are available (3002, 8080)
2. Verify Windows Firewall isn't blocking the app
3. Check Event Viewer for error details
4. Try running as Administrator

### Missing Dependencies

**Problem**: Error about missing node modules

**Solution**:
```bash
npm install
npm rebuild
```

## Distribution

### Sharing the Installer

1. **Upload to cloud storage**:
   - Google Drive
   - Dropbox
   - OneDrive
   - GitHub Releases

2. **Create a download page**:
   - Include system requirements
   - Installation instructions
   - Screenshots

3. **Version tracking**:
   - Use semantic versioning
   - Maintain changelog
   - Archive previous versions

### Code Signing (Optional)

For production distribution, consider code signing:

1. Obtain a code signing certificate
2. Add to `electron-builder.json`:
   ```json
   {
     "win": {
       "certificateFile": "path/to/cert.pfx",
       "certificatePassword": "password"
     }
   }
   ```

## File Sizes

Expected installer sizes:
- **NSIS Installer**: ~150-250 MB
- **Portable**: ~150-250 MB

Sizes vary based on:
- Included dependencies
- Compression settings
- Resource files

## Security Notes

1. **Administrator Rights**: The NSIS installer requests admin privileges to:
   - Write to Program Files
   - Create system-level directories
   - Register application

2. **Firewall**: Users may need to allow the app through Windows Firewall for:
   - Backend server communication
   - Real-time protection features

3. **Antivirus**: Some antivirus software may flag unsigned installers as potentially unwanted

## Next Steps

After building the installer:

1. ✅ Test installation on a clean VM
2. ✅ Verify all features work correctly
3. ✅ Test uninstallation process
4. ✅ Check data persistence across reinstalls
5. ✅ Document known issues
6. ✅ Create user guide

## Support

For issues with building or installing:
- Check documentation in `docs/` folder
- Review GitHub issues
- Contact: contact@nebulashield.com

---

**Last Updated**: November 2025  
**Version**: 0.1.0
