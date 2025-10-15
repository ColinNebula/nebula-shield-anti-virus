# 🚀 BUILD EXE INSTALLER

## Nebula Shield Anti-Virus - Professional Windows Installer

**Created by Colin Nebula for Nebula3ddev.com**

---

## ✅ What Was Created

I've created a professional Windows installer using **Inno Setup**:

### 📦 Files Created:

1. **`nebula-shield-setup.iss`** - Inno Setup script
   - Professional Windows installer configuration
   - Includes ALL 9 logos and assets
   - Creates desktop shortcut with icon
   - Creates Start Menu folder with icons
   - Auto-installs Node.js dependencies
   - Initializes databases
   - Beautiful wizard interface

2. **`installer-info.txt`** - Welcome screen text
   - Displays before installation
   - Shows features and requirements

3. **`startup-scripts/`** - Batch files
   - `Start-Nebula-Shield.bat` - Launch all services
   - `Start-Backend-Only.bat` - Backend only
   - `Build-Production.bat` - Production build

---

## 🔧 Prerequisites to Build the EXE

### You Need Inno Setup Installed

**Download:** https://jrsoftware.org/isdl.php

1. Download **Inno Setup 6.x** (latest version)
2. Install with default options
3. Done! ✅

---

## 🎯 How to Build the EXE Installer

### Method 1: Using Inno Setup GUI (Easiest)

1. **Open Inno Setup Compiler**
2. **File → Open** → Browse to:
   ```
   z:\Directory\projects\nebula-shield-anti-virus\installer\nebula-shield-setup.iss
   ```
3. **Build → Compile** (or press Ctrl+F9)
4. **Done!** The installer will be in:
   ```
   z:\Directory\projects\nebula-shield-anti-virus\installer\output\
   NebulaShield-Setup-v1.0.0.exe
   ```

### Method 2: Using Command Line

```powershell
cd z:\Directory\projects\nebula-shield-anti-virus\installer

# Compile the installer
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" nebula-shield-setup.iss
```

---

## 📦 What the EXE Installer Does

When users run `NebulaShield-Setup-v1.0.0.exe`:

1. **Welcome Screen** - Shows app info and features
2. **License Agreement** - Displays MIT license
3. **Destination Folder** - Default: `C:\Program Files\Nebula Shield`
4. **Components Selection** - Choose what to install
5. **Start Menu Folder** - Default: `Nebula Shield`
6. **Create Icons** - Desktop & Quick Launch options
7. **Installation Progress** - Copies files, installs dependencies
8. **Completion** - Option to launch immediately

### ✨ Automatic Actions:

- ✅ Copies all application files
- ✅ Installs ALL 9 logos to public/ folder
- ✅ Creates `.env` file from template
- ✅ Installs Node.js dependencies (frontend + backend)
- ✅ Initializes SQLite databases
- ✅ Creates desktop shortcut with Nebula Shield icon
- ✅ Creates Start Menu folder with 3 shortcuts (all with icons)
- ✅ Sets proper folder permissions

---

## 🎨 Logos Included in EXE

The installer includes ALL logos:

```
✅ logo.svg
✅ logo192.png
✅ logo512.png
✅ logo-horizontal.svg
✅ logo192.svg
✅ logo32.svg
✅ favicon.ico (used for desktop & Start Menu icons)
✅ mech2.png
✅ manifest.json
```

**Desktop and Start Menu shortcuts use the favicon.ico icon!**

---

## 🖼️ What Users Get After Installation

### Desktop:
- 🛡️ **Nebula Shield** shortcut (with logo icon)

### Start Menu → Nebula Shield:
- **Nebula Shield** - Launch all services (with logo)
- **Nebula Shield (Backend Only)** - Backend only (with logo)
- **Build Production** - Create production build (with logo)
- **Installation Folder** - Open install folder
- **README** - View documentation
- **Uninstall** - Remove application

### Installation Folder:
```
C:\Program Files\Nebula Shield\
├── public/               ← ALL 9 LOGOS HERE!
│   ├── logo.svg
│   ├── logo192.png
│   ├── logo512.png
│   ├── favicon.ico       ← Used for icons
│   └── ... (all logos)
├── src/
├── backend/
├── Start-Nebula-Shield.bat
├── Start-Backend-Only.bat
├── Build-Production.bat
└── README.md
```

---

## 📋 After Building the EXE

### The installer will be here:
```
z:\Directory\projects\nebula-shield-anti-virus\installer\output\
NebulaShield-Setup-v1.0.0.exe
```

### File size: ~50 MB (without node_modules, added during install)

### You can:
- ✅ Run it on this PC
- ✅ Copy to other Windows PCs
- ✅ Share with users
- ✅ Upload to website
- ✅ Distribute freely (MIT license)

---

## 🚀 Quick Build Commands

```powershell
# Navigate to installer folder
cd z:\Directory\projects\nebula-shield-anti-virus\installer

# Build the EXE (if Inno Setup is installed)
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" nebula-shield-setup.iss

# The EXE will be in: output\NebulaShield-Setup-v1.0.0.exe
```

---

## ⚙️ Installer Features

### Professional Features:
✅ **Modern wizard interface** - Beautiful UI  
✅ **Progress indicators** - Real-time status  
✅ **Component selection** - Choose what to install  
✅ **Desktop integration** - Icons with logos  
✅ **Automatic dependencies** - npm install during setup  
✅ **Database initialization** - Ready to use  
✅ **Clean uninstaller** - Complete removal  

### Branding:
✅ **Custom icon** - Uses favicon.ico  
✅ **Branded welcome screen** - Professional appearance  
✅ **All logos included** - Complete branding package  
✅ **Shortcuts with icons** - Desktop & Start Menu  

---

## 🔧 Customizing the Installer

Edit `nebula-shield-setup.iss` to customize:

```pascal
#define MyAppName "Nebula Shield Anti-Virus"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Colin Nebula - Nebula3ddev.com"
#define MyAppURL "https://nebula3ddev.com"
```

Change:
- App name
- Version number
- Publisher info
- Default installation folder
- Icons and graphics
- Files to include
- Start Menu entries

---

## 🆘 Troubleshooting

### "Inno Setup not found"
**Solution:** Install from https://jrsoftware.org/isdl.php

### "Cannot find source files"
**Solution:** Make sure you're in the correct directory and all source files exist

### "Compilation errors"
**Solution:** Check the Inno Setup compiler output window for specific errors

---

## 📞 Support

**Build Issues:**
- See Inno Setup documentation: https://jrsoftware.org/ishelp/
- Check `nebula-shield-setup.iss` for syntax errors

**Application Issues:**
- See main README.md
- Visit https://nebula3ddev.com
- Email support@nebula3ddev.com

---

## 🎉 Ready to Build!

**To create the EXE installer:**

1. **Install Inno Setup** (if not already installed)
2. **Open:** `nebula-shield-setup.iss` in Inno Setup
3. **Click:** Build → Compile
4. **Get:** `output\NebulaShield-Setup-v1.0.0.exe`

**That's it!** You'll have a professional Windows installer with all logos! ✨

---

**Built with ❤️ by Colin Nebula for Nebula3ddev.com** 🛡️

*This installer includes ALL logos and creates a complete branded installation!*
