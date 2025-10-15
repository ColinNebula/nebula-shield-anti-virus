# Installer Build Instructions

## Step 1: Install Inno Setup (REQUIRED - Do This First!)

I've opened the Inno Setup download page in the browser.

**Action Required:**
1. Download **Inno Setup 6** from the page that just opened
2. Run the installer (use default settings)
3. Complete the installation
4. Come back here and continue to Step 2

**Direct Download Link:** https://jrsoftware.org/isdl.php

---

## Step 2: Build the Installer

Once Inno Setup is installed, run these commands:

### Option 1: One-Click Build (Recommended)
```powershell
cd Z:\Directory\projects\nebula-shield-anti-virus\installer
.\build-all.ps1
```

### Option 2: Step-by-Step
```powershell
cd Z:\Directory\projects\nebula-shield-anti-virus\installer

# Step 1: Prepare files
.\build-installer.ps1

# Step 2: Create installer
.\build-inno-installer.ps1
```

---

## Step 3: Test the Installer

After the build completes successfully:

```powershell
cd Z:\Directory\projects\nebula-shield-anti-virus\installer\output
.\NebulaShield-Setup-1.0.0.exe
```

**What to expect:**
- Installer wizard will open
- It will check for Node.js
- You'll choose installation location
- Services will be installed
- Application will launch in browser

---

## Step 4: Verify Installation

After installation completes:

1. **Check Services:**
   - Press `Win + R`, type `services.msc`, press Enter
   - Look for "Nebula Shield" services
   - Both should be "Running"

2. **Test Application:**
   - Browser should open to http://localhost:3000
   - Register/login to test features
   - Try a file scan

3. **Check Logs (if issues):**
   - C:\Program Files\Nebula Shield\data\logs\backend-service.log
   - C:\Program Files\Nebula Shield\data\logs\auth-service.log

---

## Current Status

✅ Build scripts ready
✅ C++ backend built (0.26 MB)
✅ Node.js installed (v22.19.0)
✅ Dependencies installed
✅ Disk space available (26.54 GB)

⚠️ **Action Needed:** Install Inno Setup (download page is open in browser)

---

## After Inno Setup Installation

Once you've installed Inno Setup:

1. **Close and reopen PowerShell** (to refresh PATH)
2. **Run the build:**
   ```powershell
   cd Z:\Directory\projects\nebula-shield-anti-virus\installer
   .\build-all.ps1
   ```
3. **Wait for build to complete** (may take 2-5 minutes)
4. **Find your installer** at:
   ```
   Z:\Directory\projects\nebula-shield-anti-virus\installer\output\NebulaShield-Setup-1.0.0.exe
   ```

---

## Troubleshooting

**"Inno Setup not found" after installation:**
- Close PowerShell and open a new window
- Inno Setup is installed to: `C:\Program Files (x86)\Inno Setup 6\`

**Build fails with npm errors:**
```powershell
npm install
cd backend
npm install
```

**Backend not found:**
```powershell
cd backend\build
cmake --build . --config Release
```

---

## Need Help?

- Check `installer/QUICK_START.md` for quick reference
- Check `installer/README.md` for detailed documentation
- Check `INSTALLATION.md` for end-user guide

---

## Summary

**Right Now:**
1. 📥 Download and install Inno Setup (link is open)
2. ⏸️ Wait for installation to complete

**After Inno Setup is installed:**
3. ▶️ Run `.\build-all.ps1` in the installer directory
4. ✅ Test the generated installer
5. 🎉 Distribute to users!
