# Quick Service Troubleshooting Script
# Run this as Administrator!

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   Nebula Shield - Service Troubleshooter" -ForegroundColor Cyan
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

# Navigate to installation directory
$installPath = "C:\Program Files\Nebula Shield"
if (-not (Test-Path $installPath)) {
    Write-Host "ERROR: Installation not found at $installPath" -ForegroundColor Red
    pause
    exit 1
}

Write-Host "✓ Installation found: $installPath" -ForegroundColor Green
Set-Location $installPath
Write-Host ""

# Function to test port
function Test-Port {
    param($port)
    try {
        $connection = New-Object System.Net.Sockets.TcpClient("localhost", $port)
        $connection.Close()
        return $true
    } catch {
        return $false
    }
}

# Check Node.js
Write-Host "Checking Node.js..." -ForegroundColor Yellow
try {
    $nodeVersion = & node --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Node.js installed: $nodeVersion" -ForegroundColor Green
    } else {
        Write-Host "✗ Node.js not found or error" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Node.js not found in PATH" -ForegroundColor Red
}
Write-Host ""

# Check service files exist
Write-Host "Checking service files..." -ForegroundColor Yellow
$files = @(
    "nebula_shield_backend.exe",
    "auth-server\auth-server.js",
    "frontend-server\node_modules\serve\build\main.js"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "✓ Found: $file" -ForegroundColor Green
    } else {
        Write-Host "✗ Missing: $file" -ForegroundColor Red
    }
}
Write-Host ""

# Check databases
Write-Host "Checking databases..." -ForegroundColor Yellow
if (Test-Path "data\auth.db") {
    Write-Host "✓ Auth database exists" -ForegroundColor Green
} else {
    Write-Host "! Auth database will be created on first run" -ForegroundColor Yellow
}

if (Test-Path "data\nebula_shield.db") {
    Write-Host "✓ Antivirus database exists" -ForegroundColor Green
} else {
    Write-Host "! Antivirus database will be created on first run" -ForegroundColor Yellow
}
Write-Host ""

# Check current service status
Write-Host "Current service status:" -ForegroundColor Yellow
Get-Service | Where-Object {$_.Name -like "NebulaShield*"} | Format-Table Name, Status, StartType -AutoSize
Write-Host ""

# Try to start each service individually
Write-Host "Attempting to start services..." -ForegroundColor Yellow
Write-Host ""

# Auth Service
Write-Host "[1/2] Starting Auth Server..." -ForegroundColor Cyan
$result = & .\nssm.exe start NebulaShieldAuth 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Auth service started successfully" -ForegroundColor Green
    Start-Sleep -Seconds 3
    
    # Test the endpoint
    if (Test-Port 8081) {
        Write-Host "✓ Auth server responding on port 8081" -ForegroundColor Green
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8081/api/health" -UseBasicParsing -TimeoutSec 5
            Write-Host "✓ Health check passed: $($response.Content)" -ForegroundColor Green
        } catch {
            Write-Host "! Port open but health check failed: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "✗ Port 8081 not responding" -ForegroundColor Red
    }
} else {
    Write-Host "✗ Failed to start: $result" -ForegroundColor Red
    Write-Host "Checking logs..." -ForegroundColor Yellow
    if (Test-Path "data\logs\auth-error.log") {
        Write-Host "Last 10 lines of auth-error.log:" -ForegroundColor Yellow
        Get-Content "data\logs\auth-error.log" -Tail 10
    }
}
Write-Host ""

# Backend Service
Write-Host "[2/2] Starting Backend..." -ForegroundColor Cyan
$result = & .\nssm.exe start NebulaShieldBackend 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Backend service started successfully" -ForegroundColor Green
    Start-Sleep -Seconds 3
    
    # Test the endpoint
    if (Test-Port 8080) {
        Write-Host "✓ Backend responding on port 8080" -ForegroundColor Green
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8080/api/status" -UseBasicParsing -TimeoutSec 5
            Write-Host "✓ Status check passed: $($response.Content)" -ForegroundColor Green
        } catch {
            Write-Host "! Port open but status check failed: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "✗ Port 8080 not responding" -ForegroundColor Red
    }
} else {
    Write-Host "✗ Failed to start: $result" -ForegroundColor Red
    Write-Host "Checking logs..." -ForegroundColor Yellow
    if (Test-Path "data\logs\backend-error.log") {
        Write-Host "Last 10 lines of backend-error.log:" -ForegroundColor Yellow
        Get-Content "data\logs\backend-error.log" -Tail 10
    }
}
Write-Host ""

# Final status check
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   Final Service Status" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Get-Service | Where-Object {$_.Name -like "NebulaShield*"} | Format-Table Name, Status, StartType -AutoSize
Write-Host ""

# Port summary
Write-Host "Port Status:" -ForegroundColor Yellow
Write-Host "  Port 8080 (Backend):  $(if (Test-Port 8080) { '✓ Open' } else { '✗ Closed' })"
Write-Host "  Port 8081 (Auth):     $(if (Test-Port 8081) { '✓ Open' } else { '✗ Closed' })"
Write-Host "  Port 3000 (Frontend): $(if (Test-Port 3000) { '✓ Open' } else { '✗ Closed' })"
Write-Host ""

# If all running, open the app
$allRunning = (Get-Service -Name NebulaShieldAuth,NebulaShieldBackend,NebulaShieldFrontend | Where-Object {$_.Status -ne 'Running'}).Count -eq 0

if ($allRunning) {
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "   ✓ ALL SERVICES RUNNING!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Opening Nebula Shield at http://localhost:3000..." -ForegroundColor Cyan
    Start-Process "http://localhost:3000"
} else {
    Write-Host "================================================" -ForegroundColor Red
    Write-Host "   ✗ SOME SERVICES NOT RUNNING" -ForegroundColor Red
    Write-Host "================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting steps:" -ForegroundColor Yellow
    Write-Host "1. Check the error logs in: $installPath\data\logs\" -ForegroundColor White
    Write-Host "2. Verify Node.js is installed: node --version" -ForegroundColor White
    Write-Host "3. Check if ports are already in use:" -ForegroundColor White
    Write-Host "   netstat -ano | findstr :8080" -ForegroundColor Gray
    Write-Host "   netstat -ano | findstr :8081" -ForegroundColor Gray
    Write-Host "4. Try reinstalling the services:" -ForegroundColor White
    Write-Host "   .\uninstall-services.bat" -ForegroundColor Gray
    Write-Host "   .\install-services.bat" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
