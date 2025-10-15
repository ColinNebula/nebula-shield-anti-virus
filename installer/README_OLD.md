# Nebula Shield - Windows Installer

This directory contains scripts to build a complete Windows installer package for Nebula Shield Antivirus.

## Prerequisites

1. **Node.js** - Required for auth server and React build
   - Download: https://nodejs.org/en/download/

2. **Inno Setup** - Required to create the .exe installer
   - Download: https://jrsoftware.org/isdl.php
   - Install to default location (C:\Program Files (x86)\Inno Setup 6)

3. **Visual Studio** - C++ backend must be already built
   - The backend executable should exist in `backend/build/bin/Release/`

## Quick Start

### One-Click Build (Recommended)

```powershell
cd installer
.\build-all.ps1
```

This will:
1. Build the React frontend
2. Package all components (backend, auth server, frontend)
3. Download NSSM (service manager)
4. Create installer scripts
5. Compile the final .exe installer

### Step-by-Step Build

If you prefer to build in stages:

```powershell
# Step 1: Prepare installation files
.\build-installer.ps1

# Step 2: Create the .exe installer
.\build-inno-installer.ps1
```

## What Gets Installed

The installer packages includes:

### Core Components
- **C++ Backend** (`nebula_shield_backend.exe`) - Antivirus engine with real-time protection
- **Auth Server** (Node.js) - User authentication and settings management
- **React Frontend** - Web-based user interface

### Services
- **NebulaShieldBackend** - Windows service for the C++ antivirus engine
- **NebulaShieldAuth** - Windows service for the authentication server

### Tools
- **NSSM** (Non-Sucking Service Manager) - For managing Windows services
- **Service Scripts** - Install/uninstall batch files

### Data
- Signature database
- Data directories (logs, quarantine)
- Configuration files

## Installation Process

When users run the installer:

1. **Welcome Screen** - Introduction and license agreement
2. **Prerequisite Check** - Verifies Node.js is installed
3. **Directory Selection** - Default: `C:\Program Files\Nebula Shield`
4. **Component Selection** - Choose to install services
5. **Installation** - Copies files and installs services
6. **Completion** - Option to launch the application

## Post-Installation

After installation:

- **Start Menu** - Shortcut to launch Nebula Shield
- **Desktop Icon** - Optional desktop shortcut
- **Services** - Running as Windows services (auto-start on boot)
- **Access** - Open browser to http://localhost:3000

### Service Management

Services can be managed via:

```batch
# Using Windows Services
services.msc

# Using NSSM
nssm start NebulaShieldBackend
nssm stop NebulaShieldBackend
nssm restart NebulaShieldBackend
```

## Uninstallation

The uninstaller will:
1. Stop all services
2. Remove services from Windows
3. Delete application files
4. Optionally delete user data (quarantine, logs, settings)

## Installer Output

After successful build:

```
installer/
  ├── output/
  │   └── NebulaShield-Setup-1.0.0.exe  ← Distributable installer
  └── build/
      ├── backend/              ← C++ files
      ├── auth-server/          ← Node.js files
      ├── frontend/             ← React build
      ├── data/                 ← Data directories
      ├── nssm.exe              ← Service manager
      ├── install-services.bat  ← Service installer
      └── uninstall-services.bat
```

## Distribution

The installer is self-contained and can be distributed as a single file:
- **Filename**: `NebulaShield-Setup-1.0.0.exe`
- **Size**: ~50-100 MB (depending on dependencies)
- **Requirements**: Windows 10/11 x64, Node.js

## Customization

### Change Version
Edit `installer/nebula-shield.iss`:
```pascal
#define MyAppVersion "1.0.0"  ← Change this
```

### Change Install Location
Edit `installer/nebula-shield.iss`:
```pascal
DefaultDirName={autopf}\Nebula Shield  ← Change this
```

### Add/Remove Components
Edit `installer/nebula-shield.iss` in the `[Files]` section

## Troubleshooting

### "Node.js not found"
- Ensure Node.js is installed and in PATH
- Restart PowerShell after installing Node.js

### "Inno Setup not found"
- Install Inno Setup from https://jrsoftware.org/isdl.php
- Ensure it's installed to the default location

### "Backend executable not found"
- Build the C++ backend first:
  ```bash
  cd backend/build
  cmake --build . --config Release
  ```

### Services won't start
- Check that ports 8080 and 8081 are available
- Run `install-services.bat` as administrator
- Check logs in `data/logs/`

## Advanced: Manual Packaging

If you prefer to create a portable version without the installer:

1. Run only `build-installer.ps1`
2. Zip the contents of `installer/build/`
3. Distribute the ZIP file
4. Users extract and run `install-services.bat` manually

## Notes

- **Administrator Rights**: Required for service installation
- **Firewall**: May prompt to allow network access
- **Antivirus**: Other AVs may flag the installer (false positive)
- **Updates**: Rebuild installer for each new version

## Support

For issues or questions:
- Check logs in `C:\Program Files\Nebula Shield\data\logs\`
- Review service status in Windows Services
- See main README.md for application support
