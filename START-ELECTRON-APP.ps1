# Nebula Shield Anti-Virus - Electron App Launcher
# Production Application Launcher

$Host.UI.RawUI.WindowTitle = "Nebula Shield Anti-Virus - Electron App Launcher"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "        NEBULA SHIELD ANTI-VIRUS - ELECTRON" -ForegroundColor Cyan
Write-Host "             Production Application Launcher" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Check if backend is running on port 8080
Write-Host "[1/3] Checking for backend server on port 8080..." -ForegroundColor Yellow
$backendRunning = Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue

if ($backendRunning) {
    Write-Host "     Backend server already running on port 8080" -ForegroundColor Green
} else {
    Write-Host "     Backend server not detected, starting now..." -ForegroundColor Yellow
    Write-Host ""
    
    # Start the unified backend
    Write-Host "[2/3] Starting Backend Server (mock-backend.js)..." -ForegroundColor Yellow
    $backendPath = Join-Path $scriptDir "backend"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; node mock-backend.js" -WindowStyle Minimized
    
    # Wait for backend to start
    Write-Host "     Waiting for backend to initialize..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    
    # Verify backend started
    $backendRunning = Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue
    if ($backendRunning) {
        Write-Host "     Backend server started successfully" -ForegroundColor Green
    } else {
        Write-Host "     Failed to start backend server!" -ForegroundColor Red
        Write-Host "     Please check if Node.js is installed and port 8080 is available." -ForegroundColor Red
        Write-Host ""
        pause
        exit 1
    }
}

Write-Host ""
Write-Host "[3/3] Launching Electron Application..." -ForegroundColor Yellow

# Check which executable exists
$unpackedExe = Join-Path $scriptDir "dist\win-unpacked\Nebula Shield Anti-Virus.exe"
$portableExe = Join-Path $scriptDir "dist\Nebula Shield Anti-Virus 0.1.0.exe"

if (Test-Path $unpackedExe) {
    Write-Host "     Using unpacked build..." -ForegroundColor Green
    Start-Process $unpackedExe
} elseif (Test-Path $portableExe) {
    Write-Host "     Using portable executable..." -ForegroundColor Green
    Start-Process $portableExe
} else {
    Write-Host "     No built Electron app found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "     Please build the app first using one of:" -ForegroundColor Yellow
    Write-Host "       - npm run electron:build:win" -ForegroundColor Yellow
    Write-Host "       - BUILD-ELECTRON-WIN.bat" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "                     STARTUP COMPLETE" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Application is starting..." -ForegroundColor Cyan
Write-Host "Backend API: http://localhost:8080" -ForegroundColor Cyan
Write-Host "The Electron app window will open shortly" -ForegroundColor Cyan
Write-Host ""
Write-Host "To stop the backend server:" -ForegroundColor Yellow
Write-Host "   Close the minimized PowerShell window running the backend" -ForegroundColor Yellow
Write-Host ""

Start-Sleep -Seconds 3
