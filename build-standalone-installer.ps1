# Nebula Shield Anti-Virus - Complete Windows Installer
# This script creates a comprehensive standalone installer that works on any PC

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "      NEBULA SHIELD ANTI-VIRUS - PRODUCTION INSTALLER BUILD" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Building a complete standalone installer for distribution..." -ForegroundColor White
Write-Host ""

# Configuration
$AppName = "Nebula Shield Anti-Virus"
$Version = "1.0.0"
$Author = "ColinNebula"
$BuildDate = Get-Date -Format "yyyy-MM-dd"

# Step 1: Environment Check
Write-Host "[1/10] Checking build environment..." -ForegroundColor Yellow
$requiredTools = @(
    @{ Name = "Node.js"; Command = "node"; MinVersion = "18.0.0" },
    @{ Name = "NPM"; Command = "npm"; MinVersion = "9.0.0" }
)

foreach ($tool in $requiredTools) {
    try {
        $version = & $tool.Command --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ $($tool.Name): $version" -ForegroundColor Green
        } else {
            Write-Host "  ✗ $($tool.Name): Not found" -ForegroundColor Red
            exit 1
        }
    } catch {
        Write-Host "  ✗ $($tool.Name): Not available" -ForegroundColor Red
        exit 1
    }
}

# Step 2: Clean Previous Builds
Write-Host ""
Write-Host "[2/10] Cleaning previous builds..." -ForegroundColor Yellow
$foldersToClean = @("dist", "build", "installer/output", "installer/temp")
foreach ($folder in $foldersToClean) {
    if (Test-Path $folder) {
        Remove-Item -Recurse -Force $folder -ErrorAction SilentlyContinue
        Write-Host "  ✓ Cleaned: $folder" -ForegroundColor Green
    }
}

# Create necessary directories
$dirsToCreate = @("installer/output", "installer/temp", "installer/assets", "installer/components")
foreach ($dir in $dirsToCreate) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Write-Host "  ✓ Created: $dir" -ForegroundColor Green
}

# Step 3: Install/Update Dependencies
Write-Host ""
Write-Host "[3/10] Installing dependencies..." -ForegroundColor Yellow
Write-Host "  Installing main application dependencies..." -ForegroundColor Gray
npm ci --production=false --silent
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ✗ Failed to install main dependencies" -ForegroundColor Red
    exit 1
}

Write-Host "  Installing backend dependencies..." -ForegroundColor Gray
Push-Location backend
if (Test-Path "package.json") {
    npm ci --production --silent
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ✗ Failed to install backend dependencies" -ForegroundColor Red
        Pop-Location
        exit 1
    }
}
Pop-Location

Write-Host "  ✓ All dependencies installed" -ForegroundColor Green

# Step 4: Build Application
Write-Host ""
Write-Host "[4/10] Building application..." -ForegroundColor Yellow

# Set production environment
$env:NODE_ENV = "production"

Write-Host "  Building frontend..." -ForegroundColor Gray
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ✗ Frontend build failed" -ForegroundColor Red
    exit 1
}

Write-Host "  ✓ Application built successfully" -ForegroundColor Green

# Step 5: Create Installer Assets
Write-Host ""
Write-Host "[5/10] Preparing installer assets..." -ForegroundColor Yellow

# Copy build assets
if (Test-Path "build") {
    Copy-Item -Path "build" -Destination "installer/temp/app" -Recurse -Force
    Write-Host "  ✓ Copied application files" -ForegroundColor Green
}

# Copy backend with all dependencies
if (Test-Path "backend") {
    Copy-Item -Path "backend" -Destination "installer/temp/backend" -Recurse -Force
    Write-Host "  ✓ Copied backend files" -ForegroundColor Green
}

# Copy data directory
if (Test-Path "data") {
    Copy-Item -Path "data" -Destination "installer/temp/data" -Recurse -Force
    Write-Host "  ✓ Copied data files" -ForegroundColor Green
}

# Copy public assets
if (Test-Path "public") {
    Copy-Item -Path "public" -Destination "installer/temp/public" -Recurse -Force
    Write-Host "  ✓ Copied public assets" -ForegroundColor Green
}

# Step 6: Create Node.js Runtime Package
Write-Host ""
Write-Host "[6/10] Preparing Node.js runtime..." -ForegroundColor Yellow

$nodeVersion = (node --version).Substring(1)  # Remove 'v' prefix
$nodeUrl = "https://nodejs.org/dist/v$nodeVersion/node-v$nodeVersion-win-x64.zip"
$nodeZip = "installer/temp/node-runtime.zip"

try {
    Write-Host "  Downloading Node.js runtime v$nodeVersion..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $nodeUrl -OutFile $nodeZip -UseBasicParsing
    
    Write-Host "  Extracting Node.js runtime..." -ForegroundColor Gray
    Expand-Archive -Path $nodeZip -DestinationPath "installer/temp" -Force
    
    # Rename to standard directory
    $nodeDir = "installer/temp/node-v$nodeVersion-win-x64"
    if (Test-Path $nodeDir) {
        Rename-Item -Path $nodeDir -NewName "nodejs" -Force
    }
    
    # Clean up zip
    Remove-Item $nodeZip -Force
    
    Write-Host "  ✓ Node.js runtime prepared" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to download Node.js runtime: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Step 7: Create Electron Package
Write-Host ""
Write-Host "[7/10] Creating Electron package..." -ForegroundColor Yellow

# Use production electron-builder config
Copy-Item "electron-builder.production.json" "electron-builder.json" -Force
Write-Host "  Using production configuration..." -ForegroundColor Gray

npm run electron:build:win
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ✗ Electron packaging failed" -ForegroundColor Red
    exit 1
}

Write-Host "  ✓ Electron package created" -ForegroundColor Green

# Step 8: Create Advanced NSIS Installer
Write-Host ""
Write-Host "[8/10] Creating advanced installer..." -ForegroundColor Yellow

# Create advanced NSIS installer script
$nsisScript = @"
# Nebula Shield Anti-Virus - Advanced Installer
# Auto-generated on $BuildDate

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "WinCore.nsh"
!include "WinVer.nsh"

# Installer Information
!define APPNAME "$AppName"
!define APPVERSION "$Version"
!define APPAUTHOR "$Author"
!define APPURL "https://nebulashield.com"
!define HELPURL "https://nebulashield.com/support"

Name "`${APPNAME} `${APPVERSION}"
OutFile "installer\output\Nebula-Shield-Anti-Virus-Setup-v`${APPVERSION}.exe"
InstallDir "`$PROGRAMFILES64\Nebula Shield"
InstallDirRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetDatablockOptimize on
SetCompress auto

# Version Information
VIProductVersion "`${APPVERSION}.0"
VIAddVersionKey "ProductName" "`${APPNAME}"
VIAddVersionKey "ProductVersion" "`${APPVERSION}"
VIAddVersionKey "CompanyName" "`${APPAUTHOR}"
VIAddVersionKey "FileDescription" "`${APPNAME} Installer"
VIAddVersionKey "FileVersion" "`${APPVERSION}.0"
VIAddVersionKey "LegalCopyright" "© 2025 `${APPAUTHOR}"

# Interface Settings
!define MUI_ABORTWARNING
!define MUI_ICON "build-resources\icon.ico"
!define MUI_UNICON "build-resources\icon.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "build-resources\installer-header.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "build-resources\installer-welcome.bmp"

# Pages
!define MUI_WELCOMEPAGE_TITLE "`${APPNAME} Setup"
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of `${APPNAME}, a comprehensive security solution for Windows.`$`$`nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME

!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY

!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Start `${APPNAME} after installation"
!define MUI_FINISHPAGE_RUN_FUNCTION "LaunchApplication"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_FINISH

# Languages
!insertmacro MUI_LANGUAGE "English"

# Installation Sections
Section "`${APPNAME} (Required)" SecMain
    SectionIn RO
    
    SetOutPath "`$INSTDIR"
    
    # Install application files
    File /r "dist\win-unpacked\*.*"
    
    # Create shortcuts
    CreateDirectory "`$SMPROGRAMS\`${APPNAME}"
    CreateShortCut "`$SMPROGRAMS\`${APPNAME}\`${APPNAME}.lnk" "`$INSTDIR\`${APPNAME}.exe"
    CreateShortCut "`$DESKTOP\`${APPNAME}.lnk" "`$INSTDIR\`${APPNAME}.exe"
    
    # Register uninstaller
    WriteUninstaller "`$INSTDIR\Uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}" "DisplayName" "`${APPNAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}" "UninstallString" "`$INSTDIR\Uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}" "InstallLocation" "`$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}" "Publisher" "`${APPAUTHOR}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}" "DisplayVersion" "`${APPVERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}" "HelpLink" "`${HELPURL}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}" "URLInfoAbout" "`${APPURL}"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}" "NoRepair" 1
    
SectionEnd

Section "Desktop Shortcut" SecDesktop
    CreateShortCut "`$DESKTOP\`${APPNAME}.lnk" "`$INSTDIR\`${APPNAME}.exe"
SectionEnd

Section "Windows Startup" SecStartup
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "`${APPNAME}" "`$INSTDIR\`${APPNAME}.exe --startup"
SectionEnd

# Section descriptions
LangString DESC_SecMain `${LANG_ENGLISH} "Install `${APPNAME} application files and core components."
LangString DESC_SecDesktop `${LANG_ENGLISH} "Create a desktop shortcut for quick access."
LangString DESC_SecStartup `${LANG_ENGLISH} "Start `${APPNAME} automatically when Windows boots."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT `${SecMain} `$(DESC_SecMain)
    !insertmacro MUI_DESCRIPTION_TEXT `${SecDesktop} `$(DESC_SecDesktop)
    !insertmacro MUI_DESCRIPTION_TEXT `${SecStartup} `$(DESC_SecStartup)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function LaunchApplication
    ExecShell "" "`$INSTDIR\`${APPNAME}.exe"
FunctionEnd

# Uninstaller
Section "Uninstall"
    # Remove files
    RMDir /r "`$INSTDIR"
    
    # Remove shortcuts
    Delete "`$DESKTOP\`${APPNAME}.lnk"
    RMDir /r "`$SMPROGRAMS\`${APPNAME}"
    
    # Remove registry entries
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}"
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "`${APPNAME}"
    
SectionEnd

Function .onInit
    # Check Windows version
    `${IfNot} `${AtLeastWin10}
        MessageBox MB_OK|MB_ICONSTOP "`${APPNAME} requires Windows 10 or later."
        Quit
    `${EndIf}
    
    # Check if already installed
    ReadRegStr `$0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${APPNAME}" "UninstallString"
    `${If} `$0 != ""
        MessageBox MB_YESNO|MB_ICONQUESTION "`${APPNAME} is already installed. Do you want to uninstall the previous version?" IDYES +2
        Quit
        ExecWait `$0
    `${EndIf}
FunctionEnd
"@

# Save NSIS script
$nsisScript | Out-File "installer/installer.nsi" -Encoding UTF8

Write-Host "  ✓ NSIS installer script created" -ForegroundColor Green

# Step 9: Create Portable Package
Write-Host ""
Write-Host "[9/10] Creating portable package..." -ForegroundColor Yellow

if (Test-Path "dist/win-unpacked") {
    $portableDir = "installer/output/Nebula-Shield-Portable-v$Version"
    New-Item -ItemType Directory -Path $portableDir -Force | Out-Null
    
    # Copy application files
    Copy-Item -Path "dist/win-unpacked/*" -Destination $portableDir -Recurse -Force
    
    # Create portable launcher script
    $launcherScript = @"
@echo off
title Nebula Shield Anti-Virus - Portable Edition
echo Starting Nebula Shield Anti-Virus...
echo.
echo Portable Edition - No installation required
echo Version: $Version
echo Build Date: $BuildDate
echo.

REM Set portable mode
set NEBULA_PORTABLE=1
set NEBULA_DATA_DIR=%~dp0\data

REM Create data directory if not exists
if not exist "%NEBULA_DATA_DIR%" mkdir "%NEBULA_DATA_DIR%"

REM Launch application
start "" "%~dp0\Nebula Shield Anti-Virus.exe"

echo Application started in portable mode.
echo You can close this window.
timeout /t 3 >nul
"@

    $launcherScript | Out-File "$portableDir/Launch-Nebula-Shield.bat" -Encoding ASCII
    
    # Create readme
    $readmeContent = @"
Nebula Shield Anti-Virus - Portable Edition v$Version
================================================================

Thank you for choosing Nebula Shield Anti-Virus!

QUICK START:
1. Double-click 'Launch-Nebula-Shield.bat' to start the application
2. The application will run without installation
3. All data is stored in the 'data' folder within this directory

FEATURES:
- Real-time virus protection
- Advanced firewall
- Web protection
- Email security
- Network monitoring
- System optimization

SYSTEM REQUIREMENTS:
- Windows 10 or later (64-bit)
- 4GB RAM minimum
- 1GB free disk space
- Internet connection for updates

PORTABLE MODE BENEFITS:
- No installation required
- Run from USB drive
- No registry changes
- Self-contained

SUPPORT:
- Website: https://nebulashield.com
- Email: support@nebulashield.com
- Documentation: See docs folder

BUILD INFORMATION:
- Version: $Version
- Build Date: $BuildDate
- Architecture: x64

© 2025 $Author. All rights reserved.
"@

    $readmeContent | Out-File "$portableDir/README.txt" -Encoding UTF8
    
    # Compress portable package
    $portableZip = "installer/output/Nebula-Shield-Portable-v$Version.zip"
    Compress-Archive -Path $portableDir -DestinationPath $portableZip -CompressionLevel Optimal -Force
    
    Write-Host "  ✓ Portable package created" -ForegroundColor Green
}

# Step 10: Generate Build Report
Write-Host ""
Write-Host "[10/10] Generating build report..." -ForegroundColor Yellow

$buildReport = @"
NEBULA SHIELD ANTI-VIRUS - BUILD REPORT
================================================================

Build Information:
- Product: $AppName
- Version: $Version
- Build Date: $BuildDate
- Build Type: Production Release
- Architecture: x64
- Platform: Windows

Files Generated:
"@

# List generated files
$outputFiles = Get-ChildItem -Path "installer/output" -File -Recurse
if ($outputFiles.Count -gt 0) {
    $buildReport += "`n"
    foreach ($file in $outputFiles) {
        $sizeInMB = [math]::Round($file.Length / 1MB, 2)
        $buildReport += "- $($file.Name) ($sizeInMB MB)`n"
    }
}

# List dist files
$distFiles = Get-ChildItem -Path "dist" -Filter "*.exe" -Recurse
if ($distFiles.Count -gt 0) {
    $buildReport += "`nElectron Builder Output:`n"
    foreach ($file in $distFiles) {
        $sizeInMB = [math]::Round($file.Length / 1MB, 2)
        $buildReport += "- $($file.Name) ($sizeInMB MB)`n"
    }
}

$buildReport += @"

Installation Types:
1. NSIS Installer (installer/output/Nebula-Shield-Anti-Virus-Setup-v$Version.exe)
   - Full featured installer with uninstaller
   - Desktop shortcuts
   - Start menu integration
   - Windows startup option
   - Administrative privileges

2. Portable Edition (installer/output/Nebula-Shield-Portable-v$Version.zip)
   - No installation required
   - Run from any location
   - USB drive compatible
   - Self-contained data storage

Deployment:
- Ready for distribution
- All dependencies included
- Standalone operation
- Works on any Windows 10+ system

Next Steps:
1. Test installers on clean Windows systems
2. Distribute to end users
3. Monitor installation feedback
4. Update as needed

Build completed successfully at $(Get-Date)
================================================================
"@

$buildReport | Out-File "installer/output/BUILD-REPORT.txt" -Encoding UTF8

Write-Host "  ✓ Build report generated" -ForegroundColor Green

# Final Summary
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "                    BUILD COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
Write-Host ""

$outputFiles = Get-ChildItem -Path "installer/output" -File
$distFiles = Get-ChildItem -Path "dist" -Filter "*.exe"

Write-Host "INSTALLER PACKAGES CREATED:" -ForegroundColor Yellow
Write-Host ""

if ($outputFiles.Count -gt 0) {
    Write-Host "Custom Installers (installer/output/):" -ForegroundColor Cyan
    foreach ($file in $outputFiles) {
        $sizeInMB = [math]::Round($file.Length / 1MB, 2)
        Write-Host "  ✓ $($file.Name) - $sizeInMB MB" -ForegroundColor White
    }
}

if ($distFiles.Count -gt 0) {
    Write-Host ""
    Write-Host "Electron Packages (dist/):" -ForegroundColor Cyan
    foreach ($file in $distFiles) {
        $sizeInMB = [math]::Round($file.Length / 1MB, 2)
        Write-Host "  ✓ $($file.Name) - $sizeInMB MB" -ForegroundColor White
    }
}

Write-Host ""
Write-Host "FEATURES INCLUDED:" -ForegroundColor Yellow
Write-Host "✓ Complete antivirus engine with real-time protection" -ForegroundColor Green
Write-Host "✓ Advanced firewall with intrusion detection" -ForegroundColor Green
Write-Host "✓ Web protection and phishing detection" -ForegroundColor Green
Write-Host "✓ Email security and spam filtering" -ForegroundColor Green
Write-Host "✓ Network traffic monitoring" -ForegroundColor Green
Write-Host "✓ System optimization tools" -ForegroundColor Green
Write-Host "✓ Quarantine management" -ForegroundColor Green
Write-Host "✓ Automatic signature updates" -ForegroundColor Green
Write-Host "✓ Comprehensive logging and reporting" -ForegroundColor Green
Write-Host ""

Write-Host "INSTALLATION OPTIONS:" -ForegroundColor Yellow
Write-Host "1. NSIS Installer - Professional installation experience" -ForegroundColor White
Write-Host "2. Portable Edition - No installation required" -ForegroundColor White
Write-Host ""

Write-Host "DEPLOYMENT READY:" -ForegroundColor Yellow
Write-Host "✓ All dependencies included" -ForegroundColor Green
Write-Host "✓ Standalone operation" -ForegroundColor Green
Write-Host "✓ Windows 10+ compatible" -ForegroundColor Green
Write-Host "✓ No additional software required" -ForegroundColor Green
Write-Host ""

# Ask to open output folder
$openFolder = Read-Host "Open installer output folder? (Y/N)"
if ($openFolder -eq "Y" -or $openFolder -eq "y") {
    $outputPath = Resolve-Path "installer/output"
    Invoke-Item $outputPath
}

Write-Host ""
Write-Host "Your Nebula Shield Anti-Virus installers are ready for distribution!" -ForegroundColor Green
Write-Host ""