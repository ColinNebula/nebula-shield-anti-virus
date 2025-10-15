# Nebula Shield Installer Build Script
# This script creates a Windows installer package using Inno Setup

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Nebula Shield Installer Builder" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$InstallerDir = $PSScriptRoot
$OutputDir = Join-Path $InstallerDir "output"
$BuildDir = Join-Path $InstallerDir "build"

# Clean previous builds
Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
if (Test-Path $OutputDir) { Remove-Item -Recurse -Force $OutputDir }
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Path $OutputDir | Out-Null
New-Item -ItemType Directory -Path $BuildDir | Out-Null

# Step 1: Build React Frontend
Write-Host "`nBuilding React frontend..." -ForegroundColor Green
Set-Location $ProjectRoot
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "React build failed!" -ForegroundColor Red
    exit 1
}

# Step 2: Copy C++ Backend
Write-Host "`nCopying C++ backend..." -ForegroundColor Green
$BackendSource = Join-Path $ProjectRoot "backend\build\bin\Release"
$BackendDest = Join-Path $BuildDir "backend"
Copy-Item -Recurse -Path $BackendSource -Destination $BackendDest

# Step 3: Copy Auth Server
Write-Host "`nCopying Auth server..." -ForegroundColor Green
$AuthDest = Join-Path $BuildDir "auth-server"
New-Item -ItemType Directory -Path $AuthDest | Out-Null
Copy-Item -Path (Join-Path $ProjectRoot "backend\auth-server.js") -Destination $AuthDest
Copy-Item -Path (Join-Path $ProjectRoot "backend\.env") -Destination $AuthDest -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $ProjectRoot "backend\package.json") -Destination $AuthDest
Copy-Item -Path (Join-Path $ProjectRoot "backend\package-lock.json") -Destination $AuthDest

# Install production dependencies for auth server
Write-Host "`nInstalling auth server dependencies..." -ForegroundColor Green
Set-Location $AuthDest
npm install --production

# Step 4: Copy React Build
Write-Host "`nCopying React build..." -ForegroundColor Green
$FrontendDest = Join-Path $BuildDir "frontend"
Copy-Item -Recurse -Path (Join-Path $ProjectRoot "build") -Destination $FrontendDest

# Step 4.5: Create Frontend Server Package
Write-Host "`nCreating frontend server package..." -ForegroundColor Green
$FrontendServerDest = Join-Path $BuildDir "frontend-server"
New-Item -ItemType Directory -Path $FrontendServerDest | Out-Null

# Create package.json for frontend server
$FrontendServerPackageJson = @"
{
  "name": "nebula-shield-frontend",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "serve": "^14.2.1"
  }
}
"@
Set-Content -Path (Join-Path $FrontendServerDest "package.json") -Value $FrontendServerPackageJson

# Install serve package
Write-Host "`nInstalling frontend server dependencies..." -ForegroundColor Green
Set-Location $FrontendServerDest
npm install --production
Set-Location $ProjectRoot

# Step 5: Copy Data Directory Structure
Write-Host "`nCreating data directory structure..." -ForegroundColor Green
$DataDest = Join-Path $BuildDir "data"
New-Item -ItemType Directory -Path $DataDest | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DataDest "logs") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DataDest "quarantine") | Out-Null

# Copy signature database
if (Test-Path (Join-Path $BackendSource "signatures.db")) {
    Copy-Item -Path (Join-Path $BackendSource "signatures.db") -Destination $DataDest
}

# Step 6: Create Service Installer Scripts
Write-Host "`nCreating service installer scripts..." -ForegroundColor Green

# Backend service installer
$BackendServiceScript = @"
@echo off
echo Installing Nebula Shield Backend Service...

nssm install NebulaShieldBackend "%~dp0backend\nebula_shield_backend.exe"
nssm set NebulaShieldBackend AppDirectory "%~dp0"
nssm set NebulaShieldBackend DisplayName "Nebula Shield Antivirus Backend"
nssm set NebulaShieldBackend Description "Real-time antivirus protection engine"
nssm set NebulaShieldBackend Start SERVICE_AUTO_START
nssm set NebulaShieldBackend AppStdout "%~dp0data\logs\backend-service.log"
nssm set NebulaShieldBackend AppStderr "%~dp0data\logs\backend-error.log"

echo Backend service installed successfully!
pause
"@
Set-Content -Path (Join-Path $BuildDir "install-backend-service.bat") -Value $BackendServiceScript

# Auth server service installer
$AuthServiceScript = @"
@echo off
echo Installing Nebula Shield Auth Service...

nssm install NebulaShieldAuth "C:\Program Files\nodejs\node.exe" "auth-server\auth-server.js"
nssm set NebulaShieldAuth AppDirectory "%~dp0"
nssm set NebulaShieldAuth DisplayName "Nebula Shield Auth Server"
nssm set NebulaShieldAuth Description "User authentication and settings management"
nssm set NebulaShieldAuth Start SERVICE_AUTO_START
nssm set NebulaShieldAuth AppStdout "%~dp0data\logs\auth-service.log"
nssm set NebulaShieldAuth AppStderr "%~dp0data\logs\auth-error.log"

echo Auth service installed successfully!
pause
"@
Set-Content -Path (Join-Path $BuildDir "install-auth-service.bat") -Value $AuthServiceScript

# Frontend server service installer
$FrontendServiceScript = @"
@echo off
echo Installing Nebula Shield Frontend Service...

nssm install NebulaShieldFrontend "C:\Program Files\nodejs\node.exe" "frontend-server\node_modules\serve\build\main.js" "-s frontend -l 3000"
nssm set NebulaShieldFrontend AppDirectory "%~dp0"
nssm set NebulaShieldFrontend DisplayName "Nebula Shield Frontend Server"
nssm set NebulaShieldFrontend Description "Web interface server"
nssm set NebulaShieldFrontend Start SERVICE_AUTO_START
nssm set NebulaShieldFrontend AppStdout "%~dp0data\logs\frontend-service.log"
nssm set NebulaShieldFrontend AppStderr "%~dp0data\logs\frontend-error.log"

echo Frontend service installed successfully!
pause
"@
Set-Content -Path (Join-Path $BuildDir "install-frontend-service.bat") -Value $FrontendServiceScript

# Combined service installer
$InstallServicesScript = @"
@echo off
echo ========================================
echo   Nebula Shield Service Installer
echo ========================================
echo.

REM Check for admin rights
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
) else (
    echo ERROR: This script requires administrator privileges!
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo Installing backend service...
call "%~dp0install-backend-service.bat"

echo.
echo Installing auth service...
call "%~dp0install-auth-service.bat"

echo.
echo Installing frontend service...
call "%~dp0install-frontend-service.bat"

echo.
echo Starting services...
nssm start NebulaShieldBackend
nssm start NebulaShieldAuth
nssm start NebulaShieldFrontend

echo.
echo ========================================
echo   Installation Complete!
echo ========================================
echo.
echo Services installed and started successfully.
echo You can now access Nebula Shield at:
echo http://localhost:3000
echo.
pause
"@
Set-Content -Path (Join-Path $BuildDir "install-services.bat") -Value $InstallServicesScript

# Service uninstaller
$UninstallServicesScript = @"
@echo off
echo ========================================
echo   Nebula Shield Service Uninstaller
echo ========================================
echo.

REM Check for admin rights
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
) else (
    echo ERROR: This script requires administrator privileges!
    pause
    exit /b 1
)

echo Stopping services...
nssm stop NebulaShieldBackend
nssm stop NebulaShieldAuth
nssm stop NebulaShieldFrontend

echo Removing services...
nssm remove NebulaShieldBackend confirm
nssm remove NebulaShieldAuth confirm
nssm remove NebulaShieldFrontend confirm

echo.
echo Services uninstalled successfully!
pause
"@
Set-Content -Path (Join-Path $BuildDir "uninstall-services.bat") -Value $UninstallServicesScript

# Step 7: Create Desktop Launcher
$LauncherScript = @"
@echo off
start http://localhost:3000
"@
Set-Content -Path (Join-Path $BuildDir "Nebula Shield.bat") -Value $LauncherScript

# Step 8: Copy Documentation
Write-Host "`nCopying documentation..." -ForegroundColor Green
Copy-Item -Path (Join-Path $ProjectRoot "README.md") -Destination $BuildDir -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $ProjectRoot "SETTINGS_PERSISTENCE.md") -Destination $BuildDir -ErrorAction SilentlyContinue

# Step 9: Download NSSM (if not exists)
Write-Host "`nDownloading NSSM (Non-Sucking Service Manager)..." -ForegroundColor Green
$NssmDir = Join-Path $BuildDir "nssm"
$NssmZip = Join-Path $InstallerDir "nssm.zip"

if (!(Test-Path $NssmDir)) {
    $NssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    Invoke-WebRequest -Uri $NssmUrl -OutFile $NssmZip
    Expand-Archive -Path $NssmZip -DestinationPath $InstallerDir
    Move-Item -Path (Join-Path $InstallerDir "nssm-2.24") -Destination $NssmDir
    Remove-Item $NssmZip
}

# Copy appropriate NSSM executable
Copy-Item -Path (Join-Path $NssmDir "win64\nssm.exe") -Destination $BuildDir

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "`nBuild output: $BuildDir" -ForegroundColor Cyan
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Run build-inno-installer.ps1 to create the .exe installer"
Write-Host "2. Or manually run the Inno Setup compiler with nebula-shield.iss"
Write-Host ""
