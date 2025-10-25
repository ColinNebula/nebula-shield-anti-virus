# Nebula Shield Anti-Virus - Complete Startup Script
# Ensures all servers are running before launching the app

Write-Host "`n🛡️  Starting Nebula Shield Anti-Virus..." -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$ErrorActionPreference = "Continue"
$projectRoot = $PSScriptRoot
$backendPath = Join-Path $projectRoot "backend"

# Function to check if a port is in use
function Test-Port {
    param([int]$Port)
    try {
        $connection = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
        return $connection -ne $null
    } catch {
        return $false
    }
}

# Function to kill process on port
function Stop-ProcessOnPort {
    param([int]$Port)
    
    try {
        $processes = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | 
                     Select-Object -ExpandProperty OwningProcess -Unique
        
        if ($processes) {
            Write-Host "   Stopping existing process on port $Port..." -ForegroundColor Yellow
            foreach ($pid in $processes) {
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            }
            Start-Sleep -Seconds 1
        }
    } catch {
        # Port not in use, continue
    }
}

# Function to wait for a port to be available
function Wait-ForPort {
    param(
        [int]$Port,
        [int]$TimeoutSeconds = 30
    )
    
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        if (Test-Port $Port) {
            return $true
        }
        Start-Sleep -Milliseconds 500
        $elapsed += 0.5
    }
    return $false
}

# Check Node.js installation
Write-Host "`n[1/4] Checking Node.js installation..." -ForegroundColor Green
try {
    $nodeVersion = node --version
    Write-Host "   ✓ Node.js $nodeVersion installed" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Node.js is not installed or not in PATH" -ForegroundColor Red
    Write-Host "   Please install Node.js from https://nodejs.org/" -ForegroundColor Yellow
    pause
    exit 1
}

# Check if backend dependencies are installed
Write-Host "`n[2/4] Checking backend dependencies..." -ForegroundColor Green
$backendNodeModules = Join-Path $backendPath "node_modules"
if (-not (Test-Path $backendNodeModules)) {
    Write-Host "   Backend dependencies not found. Installing..." -ForegroundColor Yellow
    Push-Location $backendPath
    npm install
    Pop-Location
}
Write-Host "   ✓ Backend dependencies ready" -ForegroundColor Green

# Start Backend API Server (port 8080)
Write-Host "`n[3/4] Starting backend services..." -ForegroundColor Green

# Stop any existing processes on required ports
Write-Host "   Cleaning up ports..." -ForegroundColor Cyan
Stop-ProcessOnPort 8080
Stop-ProcessOnPort 8082

# Start mock backend on port 8080
Write-Host "   Starting Mock Backend Server (port 8080)..." -ForegroundColor Cyan
$mockBackendPath = Join-Path $backendPath "mock-backend.js"
if (Test-Path $mockBackendPath) {
    Start-Process powershell -ArgumentList @(
        "-NoExit",
        "-Command",
        "cd '$backendPath'; Write-Host '🔷 Mock Backend Server' -ForegroundColor Cyan; node mock-backend.js"
    ) -WindowStyle Normal
    
    Write-Host "   Waiting for Mock Backend to start..." -ForegroundColor Cyan
    if (Wait-ForPort 8080 30) {
        Write-Host "   ✓ Mock Backend Server running on port 8080" -ForegroundColor Green
    } else {
        Write-Host "   ⚠ Mock Backend may not have started correctly" -ForegroundColor Yellow
    }
} else {
    Write-Host "   ✗ mock-backend.js not found" -ForegroundColor Red
}

# Start auth server on port 8082 (optional)
Write-Host "   Starting Auth Server (port 8082)..." -ForegroundColor Cyan
$authServerPath = Join-Path $backendPath "auth-server.js"
if (Test-Path $authServerPath) {
    Start-Process powershell -ArgumentList @(
        "-NoExit",
        "-Command",
        "cd '$backendPath'; Write-Host '🔐 Auth Server' -ForegroundColor Cyan; node auth-server.js"
    ) -WindowStyle Normal
    
    Write-Host "   Waiting for Auth Server to start..." -ForegroundColor Cyan
    if (Wait-ForPort 8082 30) {
        Write-Host "   ✓ Auth Server running on port 8082" -ForegroundColor Green
    } else {
        Write-Host "   ⚠ Auth Server may not have started correctly" -ForegroundColor Yellow
    }
} else {
    Write-Host "   ⚠ auth-server.js not found (optional)" -ForegroundColor Yellow
}

# Launch the Electron app
Write-Host "`n[4/4] Launching Nebula Shield Anti-Virus..." -ForegroundColor Green

# Check if we should launch dev or production
$distPath = Join-Path $projectRoot "dist"
$portableExe = Join-Path $distPath "Nebula Shield Anti-Virus 0.1.0.exe"
$installedPath = "$env:LOCALAPPDATA\Programs\nebula-shield-anti-virus\Nebula Shield Anti-Virus.exe"

if (Test-Path $portableExe) {
    Write-Host "   Launching portable version..." -ForegroundColor Cyan
    Start-Process $portableExe
    Write-Host "   ✓ Application launched!" -ForegroundColor Green
} elseif (Test-Path $installedPath) {
    Write-Host "   Launching installed version..." -ForegroundColor Cyan
    Start-Process $installedPath
    Write-Host "   ✓ Application launched!" -ForegroundColor Green
} else {
    Write-Host "   Packaged app not found. Starting in development mode..." -ForegroundColor Yellow
    Write-Host "   Run 'npm run electron:dev' to start development mode" -ForegroundColor Yellow
    Write-Host "`n   Or build the app first with: npm run electron:build:win" -ForegroundColor Cyan
}

Write-Host "`n" + "=" * 60 -ForegroundColor Gray
Write-Host "🎉 Startup complete!" -ForegroundColor Green
Write-Host "`nBackend servers are running in separate windows." -ForegroundColor Cyan
Write-Host "Close those windows to stop the backend services." -ForegroundColor Cyan
Write-Host "`nPress any key to close this window..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
