# ONE-CLICK FIX - Nebula Shield Complete Service Repair
# Run this as Administrator!

Write-Host ""
Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   NEBULA SHIELD - COMPLETE SERVICE FIX         ║" -ForegroundColor Cyan  
Write-Host "║   One-Click Solution for Registration Issues  ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "❌ ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host ""
    Write-Host "To run as Administrator:" -ForegroundColor Yellow
    Write-Host "  1. Right-click on this file" -ForegroundColor White
    Write-Host "  2. Select 'Run with PowerShell' or 'Run as Administrator'" -ForegroundColor White
    Write-Host ""
    pause
    exit 1
}

Write-Host "✓ Running as Administrator" -ForegroundColor Green
Write-Host ""

$installPath = "C:\Program Files\Nebula Shield"

if (-not (Test-Path $installPath)) {
    Write-Host "❌ ERROR: Nebula Shield not found at: $installPath" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Nebula Shield first." -ForegroundColor Yellow
    pause
    exit 1
}

Set-Location $installPath
Write-Host "✓ Installation found" -ForegroundColor Green
Write-Host ""

# ============================================
# STEP 1: Stop All Services
# ============================================
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host " STEP 1: Stopping Services" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host ""

.\nssm.exe stop NebulaShieldAuth 2>&1 | Out-Null
.\nssm.exe stop NebulaShieldBackend 2>&1 | Out-Null
.\nssm.exe stop NebulaShieldFrontend 2>&1 | Out-Null

Start-Sleep -Seconds 2
Write-Host "✓ All services stopped" -ForegroundColor Green
Write-Host ""

# ============================================
# STEP 2: Create Directory Structure
# ============================================
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host " STEP 2: Creating Directory Structure" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host ""

# Create directories
$directories = @("data", "data\logs", "data\quarantine", "data\reports")
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  ✓ Created: $dir" -ForegroundColor Green
    } else {
        Write-Host "  ✓ Exists: $dir" -ForegroundColor Gray
    }
}
Write-Host ""

# ============================================
# STEP 3: Set Permissions
# ============================================
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host " STEP 3: Setting Permissions" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host ""

# Grant permissions on data directory
icacls "data" /grant "SYSTEM:(OI)(CI)F" /T /C /Q | Out-Null
icacls "data" /grant "Administrators:(OI)(CI)F" /T /C /Q | Out-Null  
icacls "data" /grant "Users:(OI)(CI)M" /T /C /Q | Out-Null

Write-Host "✓ Permissions configured for data directory" -ForegroundColor Green
Write-Host ""

# ============================================
# STEP 4: Create Database Files
# ============================================
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host " STEP 4: Creating Database Files" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host ""

# Create auth database
if (-not (Test-Path "data\auth.db")) {
    New-Item -ItemType File -Path "data\auth.db" -Force | Out-Null
    icacls "data\auth.db" /grant "SYSTEM:F" /C /Q | Out-Null
    icacls "data\auth.db" /grant "Administrators:F" /C /Q | Out-Null
    icacls "data\auth.db" /grant "Users:M" /C /Q | Out-Null
    Write-Host "  ✓ Created: data\auth.db" -ForegroundColor Green
} else {
    Write-Host "  ✓ Exists: data\auth.db" -ForegroundColor Gray
}

# Create antivirus database
if (-not (Test-Path "data\nebula_shield.db")) {
    New-Item -ItemType File -Path "data\nebula_shield.db" -Force | Out-Null
    icacls "data\nebula_shield.db" /grant "SYSTEM:F" /C /Q | Out-Null
    icacls "data\nebula_shield.db" /grant "Administrators:F" /C /Q | Out-Null
    icacls "data\nebula_shield.db" /grant "Users:M" /C /Q | Out-Null
    Write-Host "  ✓ Created: data\nebula_shield.db" -ForegroundColor Green
} else {
    Write-Host "  ✓ Exists: data\nebula_shield.db" -ForegroundColor Gray
}
Write-Host ""

# ============================================
# STEP 5: Configure Services
# ============================================
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host " STEP 5: Configuring Services" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host ""

# Configure Auth Service
Write-Host "  Configuring Auth Server..." -ForegroundColor Yellow
.\nssm.exe set NebulaShieldAuth AppDirectory "$installPath" | Out-Null
.\nssm.exe set NebulaShieldAuth AppStdout "$installPath\data\logs\auth-service.log" | Out-Null
.\nssm.exe set NebulaShieldAuth AppStderr "$installPath\data\logs\auth-error.log" | Out-Null
.\nssm.exe set NebulaShieldAuth AppStdoutCreationDisposition 4 | Out-Null
.\nssm.exe set NebulaShieldAuth AppStderrCreationDisposition 4 | Out-Null
Write-Host "  ✓ Auth Server configured" -ForegroundColor Green

# Configure Backend Service
Write-Host "  Configuring Backend..." -ForegroundColor Yellow
.\nssm.exe set NebulaShieldBackend AppDirectory "$installPath" | Out-Null
.\nssm.exe set NebulaShieldBackend AppStdout "$installPath\data\logs\backend-service.log" | Out-Null
.\nssm.exe set NebulaShieldBackend AppStderr "$installPath\data\logs\backend-error.log" | Out-Null
.\nssm.exe set NebulaShieldBackend AppStdoutCreationDisposition 4 | Out-Null
.\nssm.exe set NebulaShieldBackend AppStderrCreationDisposition 4 | Out-Null
Write-Host "  ✓ Backend configured" -ForegroundColor Green

# Configure Frontend Service
Write-Host "  Configuring Frontend..." -ForegroundColor Yellow
.\nssm.exe set NebulaShieldFrontend AppDirectory "$installPath" | Out-Null
.\nssm.exe set NebulaShieldFrontend AppStdout "$installPath\data\logs\frontend-service.log" | Out-Null
.\nssm.exe set NebulaShieldFrontend AppStderr "$installPath\data\logs\frontend-error.log" | Out-Null
.\nssm.exe set NebulaShieldFrontend AppStdoutCreationDisposition 4 | Out-Null
.\nssm.exe set NebulaShieldFrontend AppStderrCreationDisposition 4 | Out-Null
Write-Host "  ✓ Frontend configured" -ForegroundColor Green
Write-Host ""

# ============================================
# STEP 6: Start Services
# ============================================
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host " STEP 6: Starting Services" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host ""

# Start Backend
Write-Host "  Starting Backend..." -ForegroundColor Yellow
$result = .\nssm.exe start NebulaShieldBackend 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Backend started" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Backend: $result" -ForegroundColor Yellow
}
Start-Sleep -Seconds 2

# Start Auth
Write-Host "  Starting Auth Server..." -ForegroundColor Yellow
$result = .\nssm.exe start NebulaShieldAuth 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Auth Server started" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Auth Server: $result" -ForegroundColor Yellow
}
Start-Sleep -Seconds 2

# Start Frontend
Write-Host "  Starting Frontend..." -ForegroundColor Yellow
$result = .\nssm.exe start NebulaShieldFrontend 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Frontend started" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Frontend: $result" -ForegroundColor Yellow
}
Start-Sleep -Seconds 3
Write-Host ""

# ============================================
# STEP 7: Verify Services
# ============================================
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host " STEP 7: Verifying Services" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host ""

$services = Get-Service | Where-Object {$_.Name -like "NebulaShield*"} | Sort-Object Name

foreach ($svc in $services) {
    $icon = if ($svc.Status -eq 'Running') { '✓' } else { '✗' }
    $color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
    $padding = " " * (40 - $svc.DisplayName.Length)
    Write-Host "  $icon $($svc.DisplayName)$padding" -NoNewline -ForegroundColor $color
    Write-Host $svc.Status -ForegroundColor $color
}
Write-Host ""

# ============================================
# STEP 8: Test Endpoints
# ============================================
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host " STEP 8: Testing Endpoints" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host ""

function Test-Endpoint {
    param($url, $name, $port)
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Write-Host "  ✓ $name (port $port)" -NoNewline -ForegroundColor Green
        Write-Host " - Responding" -ForegroundColor Gray
        return $true
    } catch {
        Write-Host "  ✗ $name (port $port)" -NoNewline -ForegroundColor Red
        Write-Host " - Not responding" -ForegroundColor Gray
        return $false
    }
}

$authOk = Test-Endpoint "http://localhost:8081/api/health" "Auth Server" "8081"
$backendOk = Test-Endpoint "http://localhost:8080/api/status" "Backend" "8080"
$frontendOk = Test-Endpoint "http://localhost:3000" "Frontend" "3000"
Write-Host ""

# ============================================
# FINAL RESULT
# ============================================
$allRunning = ($services | Where-Object {$_.Status -ne 'Running'}).Count -eq 0
$allResponding = $authOk -and $backendOk -and $frontendOk

Write-Host ""
if ($allRunning -and $allResponding) {
    Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║            ✓✓✓ SUCCESS! ✓✓✓                   ║" -ForegroundColor Green
    Write-Host "║   All services running and responding!         ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "✓ Backend Service      - Running on port 8080" -ForegroundColor Green
    Write-Host "✓ Auth Server          - Running on port 8081" -ForegroundColor Green
    Write-Host "✓ Frontend Server      - Running on port 3000" -ForegroundColor Green
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGreen
    Write-Host " You can now use Nebula Shield!" -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGreen
    Write-Host ""
    Write-Host "Opening Nebula Shield..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1
    Start-Process "http://localhost:3000"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor White
    Write-Host "  1. Register a new account" -ForegroundColor Gray
    Write-Host "  2. Login with your credentials" -ForegroundColor Gray
    Write-Host "  3. Run a quick scan to test" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║            ⚠ PARTIAL SUCCESS ⚠                ║" -ForegroundColor Yellow
    Write-Host "║   Some services may not be responding          ║" -ForegroundColor Yellow
    Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    
    if (-not $allRunning) {
        Write-Host "Services not running:" -ForegroundColor Red
        $services | Where-Object {$_.Status -ne 'Running'} | ForEach-Object {
            Write-Host "  ✗ $($_.DisplayName)" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    if (-not $allResponding) {
        Write-Host "Endpoints not responding:" -ForegroundColor Red
        if (-not $authOk) { Write-Host "  ✗ Auth Server (port 8081)" -ForegroundColor Red }
        if (-not $backendOk) { Write-Host "  ✗ Backend (port 8080)" -ForegroundColor Red }
        if (-not $frontendOk) { Write-Host "  ✗ Frontend (port 3000)" -ForegroundColor Red }
        Write-Host ""
    }
    
    Write-Host "Check logs for errors:" -ForegroundColor Yellow
    Write-Host "  $installPath\data\logs\auth-error.log" -ForegroundColor Gray
    Write-Host "  $installPath\data\logs\backend-error.log" -ForegroundColor Gray
    Write-Host "  $installPath\data\logs\frontend-error.log" -ForegroundColor Gray
    Write-Host ""
    
    # Show recent errors
    Write-Host "Recent error logs:" -ForegroundColor Yellow
    Write-Host ""
    
    if (Test-Path "data\logs\auth-error.log") {
        $authErrors = Get-Content "data\logs\auth-error.log" -Tail 5 -ErrorAction SilentlyContinue
        if ($authErrors) {
            Write-Host "Auth errors:" -ForegroundColor Red
            $authErrors | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            Write-Host ""
        }
    }
    
    if (Test-Path "data\logs\backend-error.log") {
        $backendErrors = Get-Content "data\logs\backend-error.log" -Tail 5 -ErrorAction SilentlyContinue
        if ($backendErrors) {
            Write-Host "Backend errors:" -ForegroundColor Red
            $backendErrors | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            Write-Host ""
        }
    }
}

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
