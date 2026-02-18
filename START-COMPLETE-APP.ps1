# ========================================
# NEBULA SHIELD ANTI-VIRUS
# Complete Application Startup Manager
# ========================================
# Ensures all servers and services are running before launching the app
# Version: 2026.01.08

param(
    [switch]$Production,
    [switch]$Development,
    [switch]$SkipChecks,
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$projectRoot = $PSScriptRoot
$backendPath = Join-Path $projectRoot "backend"

# ========================================
# HELPER FUNCTIONS
# ========================================

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    
    $colors = @{
        "Info" = "Cyan"
        "Success" = "Green"
        "Warning" = "Yellow"
        "Error" = "Red"
        "Progress" = "Magenta"
    }
    
    $symbols = @{
        "Info" = "ℹ️"
        "Success" = "✓"
        "Warning" = "⚠"
        "Error" = "✗"
        "Progress" = "▶"
    }
    
    Write-Host "$($symbols[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Test-Port {
    param([int]$Port)
    try {
        $connection = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
        return $connection -ne $null
    } catch {
        return $false
    }
}

function Stop-ProcessOnPort {
    param([int]$Port, [string]$ServiceName)
    
    try {
        $processes = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | 
                     Select-Object -ExpandProperty OwningProcess -Unique
        
        if ($processes) {
            Write-Status "Stopping old $ServiceName process on port $Port..." "Warning"
            foreach ($pid in $processes) {
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            }
            Start-Sleep -Seconds 2
            Write-Status "$ServiceName port $Port cleared" "Success"
        }
    } catch {
        # Port not in use, continue
    }
}

function Wait-ForPort {
    param(
        [int]$Port,
        [string]$ServiceName,
        [int]$TimeoutSeconds = 30
    )
    
    $elapsed = 0
    $dots = ""
    Write-Host "   Waiting for $ServiceName to start" -NoNewline -ForegroundColor Cyan
    
    while ($elapsed -lt $TimeoutSeconds) {
        if (Test-Port $Port) {
            Write-Host " ✓" -ForegroundColor Green
            return $true
        }
        Write-Host "." -NoNewline -ForegroundColor Cyan
        Start-Sleep -Seconds 1
        $elapsed += 1
    }
    
    Write-Host " ✗ (Timeout)" -ForegroundColor Red
    return $false
}

function Test-HttpEndpoint {
    param([string]$Url, [int]$TimeoutSec = 5)
    
    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSec -ErrorAction Stop
        return $true
    } catch {
        if ($_.Exception.Response.StatusCode) {
            return $true  # Server responded, even if with error
        }
        return $false
    }
}

# ========================================
# STARTUP BANNER
# ========================================

Clear-Host
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                           ║" -ForegroundColor Cyan
Write-Host "║           🛡️  NEBULA SHIELD ANTI-VIRUS  🛡️               ║" -ForegroundColor White
Write-Host "║                                                           ║" -ForegroundColor Cyan
Write-Host "║              Complete Application Startup                 ║" -ForegroundColor Cyan
Write-Host "║                   Version 2026.01.08                      ║" -ForegroundColor Gray
Write-Host "║                                                           ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($Verbose) {
    Write-Status "Verbose mode enabled" "Info"
}

# ========================================
# STEP 1: SYSTEM CHECKS
# ========================================

Write-Host "`n[1/6] System Requirements Check" -ForegroundColor Magenta
Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray

# Check Node.js
Write-Status "Checking Node.js..." "Progress"
try {
    $nodeVersion = node --version
    Write-Status "Node.js $nodeVersion installed" "Success"
} catch {
    Write-Status "Node.js not found!" "Error"
    Write-Host "   Please install Node.js from https://nodejs.org/" -ForegroundColor Yellow
    pause
    exit 1
}

# Check npm
Write-Status "Checking npm..." "Progress"
try {
    $npmVersion = npm --version
    Write-Status "npm $npmVersion installed" "Success"
} catch {
    Write-Status "npm not found!" "Error"
    pause
    exit 1
}

# Check Python (optional for some features)
Write-Status "Checking Python..." "Progress"
try {
    $pythonVersion = python --version
    Write-Status "$pythonVersion installed" "Success"
} catch {
    Write-Status "Python not found (optional)" "Warning"
}

# ========================================
# STEP 2: DEPENDENCY INSTALLATION
# ========================================

Write-Host "`n[2/6] Dependency Installation" -ForegroundColor Magenta
Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray

# Check frontend dependencies
if (-not (Test-Path (Join-Path $projectRoot "node_modules"))) {
    Write-Status "Installing frontend dependencies..." "Progress"
    npm install --silent
    Write-Status "Frontend dependencies installed" "Success"
} else {
    Write-Status "Frontend dependencies already installed" "Success"
}

# Check backend dependencies
$backendNodeModules = Join-Path $backendPath "node_modules"
if (-not (Test-Path $backendNodeModules)) {
    Write-Status "Installing backend dependencies..." "Progress"
    Push-Location $backendPath
    npm install --silent
    Pop-Location
    Write-Status "Backend dependencies installed" "Success"
} else {
    Write-Status "Backend dependencies already installed" "Success"
}

# ========================================
# STEP 3: DATABASE VERIFICATION
# ========================================

Write-Host "`n[3/6] Database Verification" -ForegroundColor Magenta
Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray

$dbPath = Join-Path $backendPath "data\nebula_shield.db"
if (Test-Path $dbPath) {
    Write-Status "Signature database found" "Success"
    
    # Check signature count
    try {
        $sigCount = sqlite3 $dbPath "SELECT COUNT(*) FROM signatures;" 2>$null
        if ($sigCount) {
            Write-Status "Signatures loaded: $sigCount" "Success"
        }
    } catch {
        Write-Status "Database exists but couldn't verify signatures" "Warning"
    }
} else {
    Write-Status "Database not found - will be created on first run" "Warning"
}

# Check virus signatures JSON
$virusSigPath = Join-Path $backendPath "data\virus-signatures.json"
if (Test-Path $virusSigPath) {
    Write-Status "Virus signatures file found" "Success"
} else {
    Write-Status "Virus signatures file not found" "Warning"
}

# ========================================
# STEP 4: PORT CLEANUP
# ========================================

Write-Host "`n[4/6] Port Cleanup" -ForegroundColor Magenta
Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray

$ports = @{
    3000 = "React Dev Server (old)"
    3002 = "Vite Dev Server"
    8080 = "Mock Backend API"
    8081 = "Auth Server (old)"
    8082 = "Auth Server"
    3001 = "Mobile Backend"
    5173 = "Vite"
}

foreach ($port in $ports.Keys) {
    if (Test-Port $port) {
        Stop-ProcessOnPort $port $ports[$port]
    }
}

Write-Status "All ports cleared and ready" "Success"

# ========================================
# STEP 5: START BACKEND SERVICES
# ========================================

Write-Host "`n[5/6] Starting Backend Services" -ForegroundColor Magenta
Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray

# Start Mock Backend API (Port 8080)
Write-Status "Starting Mock Backend API (Port 8080)..." "Progress"
$mockBackendPath = Join-Path $backendPath "mock-backend.js"
if (Test-Path $mockBackendPath) {
    Start-Process powershell -ArgumentList @(
        "-NoExit",
        "-Command",
        "cd '$backendPath'; `$host.ui.RawUI.WindowTitle = 'Nebula Shield - Mock Backend API'; Write-Host '🔷 MOCK BACKEND API - Port 8080' -ForegroundColor Cyan; Write-Host '════════════════════════════════════════' -ForegroundColor Gray; node mock-backend.js"
    ) -WindowStyle Normal
    
    if (Wait-ForPort 8080 "Mock Backend API" 30) {
        Write-Status "Mock Backend API running on http://localhost:8080" "Success"
    } else {
        Write-Status "Mock Backend API failed to start!" "Error"
    }
} else {
    Write-Status "mock-backend.js not found!" "Error"
}

# Start Auth Server (Port 8082)
Write-Status "Starting Auth Server (Port 8082)..." "Progress"
$authServerPath = Join-Path $backendPath "auth-server.js"
if (Test-Path $authServerPath) {
    Start-Process powershell -ArgumentList @(
        "-NoExit",
        "-Command",
        "cd '$backendPath'; `$host.ui.RawUI.WindowTitle = 'Nebula Shield - Auth Server'; Write-Host '🔐 AUTHENTICATION SERVER - Port 8082' -ForegroundColor Cyan; Write-Host '════════════════════════════════════════' -ForegroundColor Gray; node auth-server.js"
    ) -WindowStyle Normal
    
    if (Wait-ForPort 8082 "Auth Server" 30) {
        Write-Status "Auth Server running on http://localhost:8082" "Success"
        
        # Verify auth endpoint
        Start-Sleep -Seconds 2
        if (Test-HttpEndpoint "http://localhost:8082/api/auth/status" 5) {
            Write-Status "Auth Server API responding" "Success"
        }
    } else {
        Write-Status "Auth Server failed to start!" "Error"
    }
} else {
    Write-Status "auth-server.js not found!" "Warning"
}

# Start C++ Backend (Optional - Port 8080)
Write-Status "Checking for C++ Backend..." "Progress"
$cppBackendExe = Join-Path $projectRoot "backend\build\bin\Release\nebula_shield_backend.exe"
if (Test-Path $cppBackendExe) {
    Write-Status "Starting C++ Backend..." "Progress"
    Start-Process -FilePath $cppBackendExe -WorkingDirectory $projectRoot -WindowStyle Minimized
    Start-Sleep -Seconds 3
    Write-Status "C++ Backend started (if needed)" "Success"
} else {
    Write-Status "C++ Backend not found (using Node.js backend)" "Info"
}

# Start Mobile Backend (Optional - Port 3001)
$mobileBackendPath = Join-Path $projectRoot "mobile-backend\server.js"
if (Test-Path $mobileBackendPath) {
    Write-Status "Starting Mobile Backend (Port 3001)..." "Progress"
    Start-Process powershell -ArgumentList @(
        "-NoExit",
        "-Command",
        "cd '$projectRoot\mobile-backend'; `$host.ui.RawUI.WindowTitle = 'Nebula Shield - Mobile Backend'; Write-Host '📱 MOBILE BACKEND - Port 3001' -ForegroundColor Cyan; Write-Host '════════════════════════════════════════' -ForegroundColor Gray; node server.js"
    ) -WindowStyle Minimized
    
    if (Wait-ForPort 3001 "Mobile Backend" 20) {
        Write-Status "Mobile Backend running on http://localhost:3001" "Success"
    }
} else {
    if ($Verbose) {
        Write-Status "Mobile Backend not found (optional)" "Info"
    }
}

# ========================================
# STEP 6: LAUNCH APPLICATION
# ========================================

Write-Host "`n[6/6] Launching Application" -ForegroundColor Magenta
Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray

if ($Development) {
    # Development mode - Start Vite dev server and Electron
    Write-Status "Starting in DEVELOPMENT mode..." "Progress"
    
    # Start Vite dev server (Port 3002)
    Write-Status "Starting Vite dev server (Port 3002)..." "Progress"
    Start-Process powershell -ArgumentList @(
        "-NoExit",
        "-Command",
        "cd '$projectRoot'; `$host.ui.RawUI.WindowTitle = 'Nebula Shield - Vite Dev Server'; Write-Host '⚡ VITE DEV SERVER - Port 3002' -ForegroundColor Cyan; Write-Host '════════════════════════════════════════' -ForegroundColor Gray; npm run dev"
    ) -WindowStyle Normal
    
    if (Wait-ForPort 3002 "Vite Dev Server" 45) {
        Write-Status "Vite dev server running on http://localhost:3002" "Success"
        
        # Wait a bit more for Vite to fully initialize
        Write-Status "Waiting for Vite to fully initialize..." "Progress"
        Start-Sleep -Seconds 5
        
        # Launch Electron
        Write-Status "Launching Electron app..." "Progress"
        Start-Process powershell -ArgumentList @(
            "-NoExit",
            "-Command",
            "cd '$projectRoot'; `$host.ui.RawUI.WindowTitle = 'Nebula Shield - Electron'; Write-Host '⚡ ELECTRON APP' -ForegroundColor Cyan; Write-Host '════════════════════════════════════════' -ForegroundColor Gray; npm run electron"
        )
        Write-Status "Electron app launched!" "Success"
    } else {
        Write-Status "Vite dev server failed to start!" "Error"
    }
    
} else {
    # Production mode - Look for built executable
    Write-Status "Starting in PRODUCTION mode..." "Progress"
    
    $appPaths = @(
        "$projectRoot\dist\Nebula Shield Anti-Virus 0.1.0.exe",
        "$env:LOCALAPPDATA\Programs\nebula-shield-anti-virus\Nebula Shield Anti-Virus.exe",
        "$projectRoot\dist\win-unpacked\Nebula Shield Anti-Virus.exe"
    )
    
    $appFound = $false
    foreach ($appPath in $appPaths) {
        if (Test-Path $appPath) {
            Write-Status "Launching application: $appPath" "Progress"
            Start-Process $appPath
            Write-Status "Application launched successfully!" "Success"
            $appFound = $true
            break
        }
    }
    
    if (-not $appFound) {
        Write-Status "Built application not found!" "Warning"
        Write-Host ""
        Write-Host "   To build the application, run:" -ForegroundColor Yellow
        Write-Host "   npm run electron:build:win" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "   Or start in development mode with:" -ForegroundColor Yellow
        Write-Host "   .\START-COMPLETE-APP.ps1 -Development" -ForegroundColor Cyan
        Write-Host ""
    }
}

# ========================================
# STARTUP SUMMARY
# ========================================

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                                                           ║" -ForegroundColor Green
Write-Host "║                  🎉 STARTUP COMPLETE! 🎉                  ║" -ForegroundColor White
Write-Host "║                                                           ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

Write-Host "📋 Running Services:" -ForegroundColor Cyan
Write-Host "   ├─ Mock Backend API:  http://localhost:8080" -ForegroundColor White
Write-Host "   ├─ Auth Server:       http://localhost:8082" -ForegroundColor White
if (Test-Port 3001) {
    Write-Host "   ├─ Mobile Backend:    http://localhost:3001" -ForegroundColor White
}
if ($Development -and (Test-Port 3002)) {
    Write-Host "   └─ Vite Dev Server:   http://localhost:3002" -ForegroundColor White
}
Write-Host ""

Write-Host "👤 Default Login Credentials:" -ForegroundColor Cyan
Write-Host "   Email:    colinnebula@gmail.com" -ForegroundColor White
Write-Host "   Password: Nebula2025!" -ForegroundColor White
Write-Host ""

Write-Host "🛠️  Management Commands:" -ForegroundColor Cyan
Write-Host "   Stop All:     .\STOP-ALL-SERVICES.ps1" -ForegroundColor Gray
Write-Host "   Restart:      .\START-COMPLETE-APP.ps1" -ForegroundColor Gray
Write-Host "   Dev Mode:     .\START-COMPLETE-APP.ps1 -Development" -ForegroundColor Gray
Write-Host ""

Write-Host "📝 Backend services are running in separate windows." -ForegroundColor Yellow
Write-Host "   Close those windows to stop individual services." -ForegroundColor Yellow
Write-Host ""

Write-Host "Press any key to close this startup window..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
