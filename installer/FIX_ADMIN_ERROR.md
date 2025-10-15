# 🚨 INSTALLER ERROR FIX

## Problem: "Script requires elevation" / Administrator privileges error

### The Error You See:
```
.\install-nebula-shield.ps1 : The script 'install-nebula-shield.ps1' cannot be run 
because it contains a "#requires" statement for running as Administrator.
The current Windows PowerShell session is not running as Administrator.
```

---

## ✅ SOLUTION - 3 Easy Methods

### Method 1: Use the Easy Launcher (RECOMMENDED) ⭐

**Simply double-click:** `INSTALL.bat`

This will automatically:
- Request administrator privileges
- Set execution policy
- Run the installer

**Done!** ✨

---

### Method 2: Run PowerShell as Administrator

1. **Press Windows Key**
2. **Type:** `PowerShell`
3. **Right-click** "Windows PowerShell"
4. **Select:** "Run as Administrator"
5. **Run these commands:**

```powershell
cd z:\Directory\projects\nebula-shield-anti-virus\installer
.\install-nebula-shield.ps1
```

---

### Method 3: Right-Click the Script

1. **Navigate to:** `z:\Directory\projects\nebula-shield-anti-virus\installer\`
2. **Hold Shift + Right-click** on `install-nebula-shield.ps1`
3. **Select:** "Run with PowerShell"
4. **Click "Yes"** when asked for admin privileges

---

## 🔧 If You Get "Execution Policy" Error

If you see:
```
cannot be loaded because running scripts is disabled on this system
```

**Run this command in PowerShell (as Administrator):**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then try the installer again.

---

## 🎯 Quick Summary

**Easiest way:**
1. Double-click `INSTALL.bat`
2. Click "Yes" when asked for admin rights
3. Done! ✅

---

## 📞 Still Having Issues?

Check the troubleshooting section in:
- `installer/README.md`
- `installer/QUICKSTART.md`

Or contact:
- 📧 support@nebula3ddev.com
- 🌐 https://nebula3ddev.com

---

**Built with ❤️ by Colin Nebula for Nebula3ddev.com** 🛡️
