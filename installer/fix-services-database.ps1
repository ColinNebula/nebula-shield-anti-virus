# Fix Nebula Shield Services - Database Path Issue
# Run this as Administrator!

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   Nebula Shield - Fix Service Database Paths" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

Write-Host "✓ Running as Administrator" -ForegroundColor Green
Write-Host ""

$installPath = "C:\Program Files\Nebula Shield"

# Check installation exists
if (-not (Test-Path $installPath)) {
    Write-Host "ERROR: Installation not found at $installPath" -ForegroundColor Red
    pause
    exit 1
}

Write-Host "✓ Installation found" -ForegroundColor Green
Set-Location $installPath
Write-Host ""

# Ensure data directory exists
if (-not (Test-Path "data")) {
    Write-Host "Creating data directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path "data" | Out-Null
    Write-Host "✓ Data directory created" -ForegroundColor Green
} else {
    Write-Host "✓ Data directory exists" -ForegroundColor Green
}
Write-Host ""

# Ensure logs directory exists
if (-not (Test-Path "data\logs")) {
    Write-Host "Creating logs directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path "data\logs" | Out-Null
    Write-Host "✓ Logs directory created" -ForegroundColor Green
} else {
    Write-Host "✓ Logs directory exists" -ForegroundColor Green
}
Write-Host ""

# Stop all services first
Write-Host "Stopping services..." -ForegroundColor Yellow
.\nssm.exe stop NebulaShieldAuth 2>&1 | Out-Null
.\nssm.exe stop NebulaShieldBackend 2>&1 | Out-Null
Start-Sleep -Seconds 2
Write-Host "✓ Services stopped" -ForegroundColor Green
Write-Host ""

# Fix Auth Service - Set proper working directory
Write-Host "Configuring Auth Service..." -ForegroundColor Yellow
.\nssm.exe set NebulaShieldAuth AppDirectory "$installPath" | Out-Null
.\nssm.exe set NebulaShieldAuth AppStdout "$installPath\data\logs\auth-service.log" | Out-Null
.\nssm.exe set NebulaShieldAuth AppStderr "$installPath\data\logs\auth-error.log" | Out-Null
Write-Host "✓ Auth service configured" -ForegroundColor Green

# Fix Backend Service - Set proper working directory  
Write-Host "Configuring Backend Service..." -ForegroundColor Yellow
.\nssm.exe set NebulaShieldBackend AppDirectory "$installPath" | Out-Null
.\nssm.exe set NebulaShieldBackend AppStdout "$installPath\data\logs\backend-service.log" | Out-Null
.\nssm.exe set NebulaShieldBackend AppStderr "$installPath\data\logs\backend-error.log" | Out-Null
Write-Host "✓ Backend service configured" -ForegroundColor Green

# Fix Frontend Service
Write-Host "Configuring Frontend Service..." -ForegroundColor Yellow
.\nssm.exe set NebulaShieldFrontend AppDirectory "$installPath" | Out-Null
.\nssm.exe set NebulaShieldFrontend AppStdout "$installPath\data\logs\frontend-service.log" | Out-Null
.\nssm.exe set NebulaShieldFrontend AppStderr "$installPath\data\logs\frontend-error.log" | Out-Null
Write-Host "✓ Frontend service configured" -ForegroundColor Green
Write-Host ""

# Start services
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   Starting Services" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Start Backend first
Write-Host "[1/3] Starting Backend..." -ForegroundColor Cyan
$result = .\nssm.exe start NebulaShieldBackend 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Backend started" -ForegroundColor Green
    Start-Sleep -Seconds 2
} else {
    Write-Host "✗ Backend failed: $result" -ForegroundColor Red
}

# Start Auth
Write-Host "[2/3] Starting Auth Server..." -ForegroundColor Cyan
$result = .\nssm.exe start NebulaShieldAuth 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Auth server started" -ForegroundColor Green
    Start-Sleep -Seconds 2
} else {
    Write-Host "✗ Auth failed: $result" -ForegroundColor Red
}

# Start Frontend
Write-Host "[3/3] Starting Frontend..." -ForegroundColor Cyan
$result = .\nssm.exe start NebulaShieldFrontend 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Frontend started" -ForegroundColor Green
    Start-Sleep -Seconds 2
} else {
    Write-Host "✗ Frontend failed: $result" -ForegroundColor Red
}
Write-Host ""

# Wait a moment for services to initialize
Write-Host "Waiting for services to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 3
Write-Host ""

# Check final status
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   Service Status" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

$services = Get-Service | Where-Object {$_.Name -like "NebulaShield*"}
foreach ($svc in $services) {
    $status = if ($svc.Status -eq 'Running') { '✓' } else { '✗' }
    $color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Host "$status $($svc.DisplayName): " -NoNewline -ForegroundColor $color
    Write-Host $svc.Status -ForegroundColor $color
}
Write-Host ""

# Test endpoints
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   Testing Endpoints" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

function Test-Endpoint {
    param($url, $name)
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Write-Host "✓ $name responded successfully" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "✗ $name not responding" -ForegroundColor Red
        return $false
    }
}

$authOk = Test-Endpoint "http://localhost:8081/api/health" "Auth Server (8081)"
$backendOk = Test-Endpoint "http://localhost:8080/api/status" "Backend (8080)"
$frontendOk = Test-Endpoint "http://localhost:3000" "Frontend (3000)"
Write-Host ""

# Show logs if services failed
$allRunning = ($services | Where-Object {$_.Status -ne 'Running'}).Count -eq 0

if (-not $allRunning) {
    Write-Host "================================================" -ForegroundColor Red
    Write-Host "   Service Logs (Last 15 Lines)" -ForegroundColor Red
    Write-Host "================================================" -ForegroundColor Red
    Write-Host ""
    
    if (Test-Path "data\logs\auth-error.log") {
        $authErrors = Get-Content "data\logs\auth-error.log" -Tail 15 -ErrorAction SilentlyContinue
        if ($authErrors) {
            Write-Host "Auth Error Log:" -ForegroundColor Yellow
            $authErrors | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
            Write-Host ""
        }
    }
    
    if (Test-Path "data\logs\backend-error.log") {
        $backendErrors = Get-Content "data\logs\backend-error.log" -Tail 15 -ErrorAction SilentlyContinue
        if ($backendErrors) {
            Write-Host "Backend Error Log:" -ForegroundColor Yellow
            $backendErrors | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
            Write-Host ""
        }
    }
}

# Summary
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

if ($allRunning -and $authOk -and $backendOk -and $frontendOk) {
    Write-Host "✓ ALL SERVICES RUNNING AND RESPONDING!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Opening Nebula Shield..." -ForegroundColor Cyan
    Start-Process "http://localhost:3000"
    Write-Host ""
    Write-Host "You can now:" -ForegroundColor White
    Write-Host "  • Register a new account" -ForegroundColor Gray
    Write-Host "  • Login with your credentials" -ForegroundColor Gray
    Write-Host "  • Run virus scans" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host "⚠ SOME ISSUES DETECTED" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor White
    Write-Host "  1. Check logs in: $installPath\data\logs\" -ForegroundColor Gray
    Write-Host "  2. Ensure Node.js is installed: node --version" -ForegroundColor Gray
    Write-Host "  3. Check ports aren't in use:" -ForegroundColor Gray
    Write-Host "     netstat -ano | findstr :8080" -ForegroundColor DarkGray
    Write-Host "     netstat -ano | findstr :8081" -ForegroundColor DarkGray
    Write-Host "     netstat -ano | findstr :3000" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
