# Quick Start - Building & Distributing Nebula Shield Installer

## Build the Installer

Simply run:
```bash
npm run build:installer
```

This will:
1. Clean previous builds
2. Install dependencies
3. Build the application
4. Create installer packages

## What You Get

After building, you'll find in the `dist/` folder:

1. **Nebula Shield Anti-Virus-0.1.0-x64.exe** 
   - Full NSIS installer
   - ~150-250 MB
   - Best for distribution

2. **Nebula Shield Anti-Virus-0.1.0-x64-portable.exe**
   - Portable version (no install needed)
   - ~150-250 MB  
   - Best for testing

## Distribute to Other Computers

### Method 1: Copy the Installer
1. Copy `Nebula Shield Anti-Virus-0.1.0-x64.exe` to target computer
2. Double-click to install
3. Follow the wizard

### Method 2: Use Portable Version
1. Copy `Nebula Shield Anti-Virus-0.1.0-x64-portable.exe` to target computer
2. Run directly (no installation)

## Requirements on Target Computer

- Windows 10/11 (64-bit)
- 4GB RAM minimum
- 500MB free space
- Administrator rights (for NSIS installer)

## Troubleshooting

**Build fails?**
- Run `npm install` first
- Make sure Node.js 18+ is installed

**Installer won't run?**
- Right-click → Run as Administrator
- Click "More info" on SmartScreen, then "Run anyway"

**Need help?**
See `INSTALLER_GUIDE.md` for detailed documentation.
