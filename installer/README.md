# 🛡️ Nebula Shield Anti-Virus - Installation Package# Nebula Shield - Windows Installer



## Professional Installation GuideThis directory contains scripts to build a complete Windows installer package for Nebula Shield Antivirus.



**Created by Colin Nebula for [Nebula3ddev.com](https://nebula3ddev.com)**## Prerequisites



---1. **Node.js** - Required for auth server and React build

   - Download: https://nodejs.org/en/download/

## 📦 Package Contents

2. **Inno Setup** - Required to create the .exe installer

This installation package includes:   - Download: https://jrsoftware.org/isdl.php

   - Install to default location (C:\Program Files (x86)\Inno Setup 6)

- ✅ Complete application source code

- ✅ All logos and branding assets (PNG, SVG, ICO)3. **Visual Studio** - C++ backend must be already built

- ✅ Backend services (Authentication & Main API)   - The backend executable should exist in `backend/build/bin/Release/`

- ✅ Frontend React application

- ✅ Database initialization scripts## Quick Start

- ✅ Production-ready configuration

- ✅ Desktop shortcuts with icons### One-Click Build (Recommended)

- ✅ Start Menu integration

- ✅ Automatic dependency installation```powershell

- ✅ Uninstallercd installer

.\build-all.ps1

---```



## 🚀 Quick InstallationThis will:

1. Build the React frontend

### Option 1: One-Click Install (Recommended)2. Package all components (backend, auth server, frontend)

3. Download NSSM (service manager)

1. **Right-click** `install-nebula-shield.ps1`4. Create installer scripts

2. Select **"Run with PowerShell"**5. Compile the final .exe installer

3. If prompted, click **"Run anyway"** or **"Yes"** to allow administrator access

4. Follow the on-screen prompts### Step-by-Step Build

5. Done! 🎉

If you prefer to build in stages:

### Option 2: Command Line Install

```powershell

```powershell# Step 1: Prepare installation files

# Open PowerShell as Administrator.\build-installer.ps1

cd path\to\installer

.\install-nebula-shield.ps1# Step 2: Create the .exe installer

```.\build-inno-installer.ps1

```

### Option 3: Custom Installation

## What Gets Installed

```powershell

# Install to custom locationThe installer packages includes:

.\install-nebula-shield.ps1 -InstallPath "D:\MyApps\Nebula Shield"

### Core Components

# Skip desktop shortcut- **C++ Backend** (`nebula_shield_backend.exe`) - Antivirus engine with real-time protection

.\install-nebula-shield.ps1 -CreateDesktopShortcut:$false- **Auth Server** (Node.js) - User authentication and settings management

- **React Frontend** - Web-based user interface

# Skip dependency installation (install manually later)

.\install-nebula-shield.ps1 -SkipDependencies### Services

```- **NebulaShieldBackend** - Windows service for the C++ antivirus engine

- **NebulaShieldAuth** - Windows service for the authentication server

---

### Tools

## ⚙️ Installation Options- **NSSM** (Non-Sucking Service Manager) - For managing Windows services

- **Service Scripts** - Install/uninstall batch files

| Parameter | Type | Default | Description |

|-----------|------|---------|-------------|### Data

| `-InstallPath` | String | `C:\Program Files\Nebula Shield` | Installation directory |- Signature database

| `-SkipDependencies` | Switch | `$false` | Skip npm install (faster, requires manual setup) |- Data directories (logs, quarantine)

| `-CreateDesktopShortcut` | Switch | `$true` | Create desktop shortcut with logo |- Configuration files

| `-CreateStartMenu` | Switch | `$true` | Add to Windows Start Menu |

| `-AutoStart` | Switch | `$false` | Launch after installation |## Installation Process



### ExamplesWhen users run the installer:



```powershell1. **Welcome Screen** - Introduction and license agreement

# Minimal installation (no shortcuts)2. **Prerequisite Check** - Verifies Node.js is installed

.\install-nebula-shield.ps1 -CreateDesktopShortcut:$false -CreateStartMenu:$false3. **Directory Selection** - Default: `C:\Program Files\Nebula Shield`

4. **Component Selection** - Choose to install services

# Fast installation (install dependencies later)5. **Installation** - Copies files and installs services

.\install-nebula-shield.ps1 -SkipDependencies6. **Completion** - Option to launch the application



# Complete custom installation## Post-Installation

.\install-nebula-shield.ps1 `

  -InstallPath "E:\Security\Nebula Shield" `After installation:

  -CreateDesktopShortcut:$true `

  -CreateStartMenu:$true `- **Start Menu** - Shortcut to launch Nebula Shield

  -AutoStart:$true- **Desktop Icon** - Optional desktop shortcut

```- **Services** - Running as Windows services (auto-start on boot)

- **Access** - Open browser to http://localhost:3000

---

### Service Management

## 📋 Prerequisites

Services can be managed via:

### Required

```batch

- **Windows 10/11** (64-bit recommended)# Using Windows Services

- **Administrator privileges**services.msc

- **Node.js 18.0.0 or higher** → [Download](https://nodejs.org/)

- **npm 8.0.0 or higher** (included with Node.js)# Using NSSM

- **At least 2GB free disk space**nssm start NebulaShieldBackend

- **4GB RAM minimum** (8GB recommended)nssm stop NebulaShieldBackend

nssm restart NebulaShieldBackend

### Optional```



- **VirusTotal API Key** (free) → [Get Key](https://www.virustotal.com/)## Uninstallation

- **Stripe Account** (for payment processing)

- **PayPal Developer Account** (alternative payments)The uninstaller will:

- **Email SMTP Server** (for notifications)1. Stop all services

2. Remove services from Windows

---3. Delete application files

4. Optionally delete user data (quarantine, logs, settings)

## 🔧 Post-Installation Configuration

## Installer Output

### 1. Configure API Keys

After successful build:

Edit the `.env` file in your installation directory:

```

```bashinstaller/

# Required for full functionality  ├── output/

REACT_APP_VIRUSTOTAL_API_KEY=your_virustotal_api_key_here  │   └── NebulaShield-Setup-1.0.0.exe  ← Distributable installer

  └── build/

# Generate a secure JWT secret      ├── backend/              ← C++ files

JWT_SECRET=your_secure_random_string_here      ├── auth-server/          ← Node.js files

      ├── frontend/             ← React build

# Optional - for premium features      ├── data/                 ← Data directories

STRIPE_SECRET_KEY=sk_live_...      ├── nssm.exe              ← Service manager

PAYPAL_CLIENT_ID=your_paypal_client_id      ├── install-services.bat  ← Service installer

```      └── uninstall-services.bat

```

**Location:** `C:\Program Files\Nebula Shield\.env`

## Distribution

### 2. Get Your Free VirusTotal API Key

The installer is self-contained and can be distributed as a single file:

1. Visit [https://www.virustotal.com/](https://www.virustotal.com/)- **Filename**: `NebulaShield-Setup-1.0.0.exe`

2. Create a free account- **Size**: ~50-100 MB (depending on dependencies)

3. Go to your profile → API Key- **Requirements**: Windows 10/11 x64, Node.js

4. Copy the API key

5. Paste it into `.env` file## Customization



### 3. Configure Email (Optional)### Change Version

Edit `installer/nebula-shield.iss`:

For email notifications and reports:```pascal

#define MyAppVersion "1.0.0"  ← Change this

```bash```

EMAIL_HOST=smtp.gmail.com

EMAIL_PORT=587### Change Install Location

EMAIL_USER=your_email@gmail.comEdit `installer/nebula-shield.iss`:

EMAIL_PASS=your_app_password```pascal

```DefaultDirName={autopf}\Nebula Shield  ← Change this

```

**Gmail Users:** Enable 2FA and create an [App Password](https://support.google.com/accounts/answer/185833)

### Add/Remove Components

### 4. Configure Firewall (Optional)Edit `installer/nebula-shield.iss` in the `[Files]` section



Allow these ports through Windows Firewall:## Troubleshooting



- **Port 3001** - Frontend (React)### "Node.js not found"

- **Port 8080** - Main Backend API- Ensure Node.js is installed and in PATH

- **Port 8082** - Authentication Server- Restart PowerShell after installing Node.js



---### "Inno Setup not found"

- Install Inno Setup from https://jrsoftware.org/isdl.php

## 🎯 Starting Nebula Shield- Ensure it's installed to the default location



### Method 1: Desktop Shortcut### "Backend executable not found"

Double-click the **"Nebula Shield"** icon on your desktop- Build the C++ backend first:

  ```bash

### Method 2: Start Menu  cd backend/build

1. Press **Windows Key**  cmake --build . --config Release

2. Type **"Nebula Shield"**  ```

3. Click the app icon

### Services won't start

### Method 3: Batch File- Check that ports 8080 and 8081 are available

Navigate to installation folder and run:- Run `install-services.bat` as administrator

- `Start-Nebula-Shield.bat` - Starts all services- Check logs in `data/logs/`

- `Start-Backend-Only.bat` - Backend services only

## Advanced: Manual Packaging

### Method 4: Manual

```powershellIf you prefer to create a portable version without the installer:

cd "C:\Program Files\Nebula Shield"

1. Run only `build-installer.ps1`

# Terminal 1 - Auth Server2. Zip the contents of `installer/build/`

node backend\auth-server.js3. Distribute the ZIP file

4. Users extract and run `install-services.bat` manually

# Terminal 2 - Main Backend

node mock-backend.js## Notes



# Terminal 3 - Frontend- **Administrator Rights**: Required for service installation

npm start- **Firewall**: May prompt to allow network access

```- **Antivirus**: Other AVs may flag the installer (false positive)

- **Updates**: Rebuild installer for each new version

---

## Support

## 📦 What Gets Installed

For issues or questions:

### Directory Structure- Check logs in `C:\Program Files\Nebula Shield\data\logs\`

- Review service status in Windows Services

```- See main README.md for application support

C:\Program Files\Nebula Shield\
├── 📁 src/                          # React source code
│   ├── components/                  # UI components
│   ├── pages/                       # Application pages
│   └── services/                    # API services
│
├── 📁 public/                       # Static assets & logos
│   ├── logo.svg                     # Main logo
│   ├── logo192.png                  # Medium logo
│   ├── logo512.png                  # Large logo
│   ├── logo-horizontal.svg          # Horizontal logo
│   ├── favicon.ico                  # Browser icon
│   └── mech2.png                    # Background asset
│
├── 📁 backend/                      # Server code
│   ├── auth-server.js               # Authentication
│   ├── quarantine-service.js        # File quarantine
│   ├── data/                        # Databases
│   │   ├── auth.db                  # User data
│   │   └── quarantine.db            # Quarantined files
│   └── quarantine_vault/            # Encrypted files
│
├── 📁 node_modules/                 # Dependencies
│
├── 📄 .env                          # Configuration
├── 📄 package.json                  # Project metadata
├── 📄 README.md                     # Documentation
│
├── 🚀 Start-Nebula-Shield.bat       # Main launcher
├── 🚀 Start-Backend-Only.bat        # Backend only
├── 🔨 Build-Production.bat          # Build script
└── 🗑️  Uninstall.ps1                # Uninstaller
```

### Desktop Shortcuts

- **Nebula Shield** - Main application launcher (with logo icon)

### Start Menu Entries

Located in: `Start Menu → Nebula Shield`

- **Nebula Shield** - Launch application
- **Nebula Shield (Backend Only)** - Start backend services
- **Installation Folder** - Open install directory

---

## 🔄 Updating Nebula Shield

### Manual Update

1. Backup your `.env` file and `backend/data/` folder
2. Delete installation directory (keep backups)
3. Run installer again
4. Restore your `.env` and data files

### Using Git (Advanced)

```powershell
cd "C:\Program Files\Nebula Shield"
git pull origin main
npm install
cd backend
npm install
```

---

## 🗑️ Uninstalling

### Option 1: Uninstall Script (Recommended)

1. Navigate to installation folder
2. Right-click `Uninstall.ps1`
3. Select **"Run with PowerShell"**
4. Confirm uninstallation

### Option 2: Manual Removal

1. Delete installation folder: `C:\Program Files\Nebula Shield`
2. Delete desktop shortcut: `Desktop\Nebula Shield.lnk`
3. Delete Start Menu folder: `Start Menu\Programs\Nebula Shield`

---

## 🐛 Troubleshooting

### Installation Fails with "Access Denied"

**Solution:** Run PowerShell as Administrator
- Right-click PowerShell → "Run as Administrator"
- Navigate to installer folder
- Run script again

### "Execution Policy" Error

**Problem:**
```
install-nebula-shield.ps1 cannot be loaded because running scripts is disabled
```

**Solution:**
```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then run installer
.\install-nebula-shield.ps1

# Restore policy after (optional)
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser
```

### Node.js Not Found

**Solution:**
1. Download Node.js from [nodejs.org](https://nodejs.org/)
2. Install LTS version
3. Restart PowerShell
4. Run installer again

### Dependencies Installation Fails

**Solution:**
```powershell
cd "C:\Program Files\Nebula Shield"

# Clear npm cache
npm cache clean --force

# Install frontend dependencies
npm install

# Install backend dependencies
cd backend
npm install
```

### Port Already in Use

**Problem:** Ports 3001, 8080, or 8082 are already in use

**Solution:**

1. **Check what's using the port:**
   ```powershell
   netstat -ano | findstr :8080
   ```

2. **Kill the process:**
   ```powershell
   taskkill /PID <process_id> /F
   ```

3. **Or change ports in `.env`:**
   ```bash
   PORT=8081
   AUTH_PORT=8083
   REACT_APP_API_URL=http://localhost:8081
   ```

### Application Won't Start

**Check:**

1. **All dependencies installed?**
   ```powershell
   cd "C:\Program Files\Nebula Shield"
   npm list
   ```

2. **Correct Node version?**
   ```powershell
   node --version  # Should be 18.0.0 or higher
   ```

3. **Check logs:**
   - Look at terminal output for errors
   - Check `backend/logs/` if exists

### Database Errors

**Solution:**
```powershell
cd "C:\Program Files\Nebula Shield\backend"

# Reinitialize databases
Remove-Item data\*.db -ErrorAction SilentlyContinue
node -e "require('./quarantine-service.js')"
```

---

## 🔒 Security Notes

### After Installation

1. **Change JWT Secret** in `.env` to a random string
2. **Set strong passwords** for admin accounts
3. **Configure firewall rules** if exposing to network
4. **Keep Node.js updated** for security patches
5. **Regularly backup** the `backend/data/` folder

### Production Deployment

If deploying to a server:

1. Use `.env.production` instead of `.env`
2. Set `NODE_ENV=production`
3. Use HTTPS (not HTTP)
4. Configure proper CORS origins
5. Enable all Helmet security headers
6. Set up regular automated backups

---

## 📊 System Requirements

### Minimum

- **OS:** Windows 10 (64-bit)
- **CPU:** Dual-core 2.0 GHz
- **RAM:** 4GB
- **Storage:** 2GB free space
- **Node.js:** 18.0.0+

### Recommended

- **OS:** Windows 11 (64-bit)
- **CPU:** Quad-core 3.0 GHz+
- **RAM:** 8GB+
- **Storage:** 5GB free space (SSD preferred)
- **Node.js:** Latest LTS version
- **Internet:** Broadband (for VirusTotal, updates)

---

## 📞 Support

### Getting Help

**Documentation:**
- 📖 Main README: `C:\Program Files\Nebula Shield\README.md`
- 📚 All docs: Installation folder

**Online:**
- 🌐 Website: [Nebula3ddev.com](https://nebula3ddev.com)
- 📧 Email: support@nebula3ddev.com
- 💬 GitHub Issues: [Report Bug](https://github.com/nebula3ddev/nebula-shield-anti-virus/issues)

**Response Times:**
- 🔴 Critical: < 24 hours
- 🟡 Bugs: < 48 hours
- 🟢 Features: < 1 week

---

## 📜 License

MIT License - Copyright (c) 2025 Colin Nebula

See `LICENSE` file for full details.

---

## 🙏 Credits

**Created with ❤️ by Colin Nebula**

- 🌐 [Nebula3ddev.com](https://nebula3ddev.com)
- 📧 contact@nebula3ddev.com
- 💼 Professional Security Software Developer

---

## 🎉 Thank You!

Thank you for choosing **Nebula Shield Anti-Virus**!

We hope you enjoy using our professional security suite.

**Stay Protected. Stay Secure.** 🛡️

---

*Last Updated: January 2025*
*Version: 1.0.0*
