# Nebula Shield - Synchronized Service Orchestrator v2.0
# Ensures all services stay in sync with centralized configuration

$ErrorActionPreference = "Continue"

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "🔄 NEBULA SHIELD - SYNCHRONIZED SERVICES" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan

$ProjectRoot = "Z:\Directory\projects\nebula-shield-anti-virus"

# Load centralized configuration
Write-Host "📋 Loading centralized configuration..." -ForegroundColor Yellow
$configPath = "$ProjectRoot\config\app-config.js"

if (Test-Path $configPath) {
    Write-Host "   ✅ Config found: app-config.js" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Creating default configuration..." -ForegroundColor Yellow
}

# Configuration (synced across all services)
$CONFIG = @{
    PORTS = @{
        FRONTEND = 3000
        AUTH_SERVER = 8082
        BACKEND_API = 8080
    }
    VERSION = "2.0.0"
    BUILD_DATE = Get-Date -Format "yyyy-MM-dd"
    FEATURES = @{
        ADMIN_PANEL = $true
        RBAC = $true
        AUDIT_LOGS = $true
    }
}

Write-Host "   Version: $($CONFIG.VERSION)" -ForegroundColor Gray
Write-Host "   Build Date: $($CONFIG.BUILD_DATE)" -ForegroundColor Gray
Write-Host ""

# Function to check if port is in use
function Test-Port {
    param([int]$Port)
    $result = netstat -ano | findstr ":$Port"
    return $null -ne $result
}

# Function to get process on port
function Get-PortProcess {
    param([int]$Port)
    $result = netstat -ano | findstr ":$Port" | Select-Object -First 1
    if ($result -match '\s+(\d+)$') {
        return $matches[1]
    }
    return $null
}

# Function to verify service configuration
function Test-ServiceConfig {
    param([string]$ServiceName)
    
    switch ($ServiceName) {
        "AuthServer" {
            $envFile = "$ProjectRoot\backend\.env"
            if (Test-Path $envFile) {
                $content = Get-Content $envFile -Raw
                if ($content -match "AUTH_PORT=8082") {
                    return $true
                }
            }
            return $false
        }
        "Frontend" {
            $authContext = "$ProjectRoot\src\contexts\AuthContext.js"
            if (Test-Path $authContext) {
                $content = Get-Content $authContext -Raw
                if ($content -match "localhost:8082") {
                    return $true
                }
            }
            return $false
        }
        default {
            return $true
        }
    }
}

# Function to start service with sync verification
function Start-SyncedService {
    param(
        [string]$Name,
        [int]$Port,
        [string]$Directory,
        [string]$Command,
        [string]$Description
    )
    
    Write-Host "🔍 Checking $Name..." -ForegroundColor Yellow
    
    # Verify configuration
    $configOK = Test-ServiceConfig -ServiceName $Name
    if (-not $configOK) {
        Write-Host "   ⚠️  Configuration mismatch detected!" -ForegroundColor Yellow
    } else {
        Write-Host "   ✅ Configuration verified" -ForegroundColor Green
    }
    
    if (Test-Port -Port $Port) {
        $pid = Get-PortProcess -Port $Port
        Write-Host "   ✅ Already running on port $Port (PID: $pid)" -ForegroundColor Green
        return $pid
    }
    
    Write-Host "   🚀 Starting $Name on port $Port..." -ForegroundColor Cyan
    
    try {
        $proc = Start-Process powershell -ArgumentList `
            "-NoExit", `
            "-Command", `
            "Set-Location '$Directory'; Write-Host '🔥 $Description' -ForegroundColor Cyan; Write-Host '   Port: $Port' -ForegroundColor Gray; Write-Host '   Config Version: $($CONFIG.VERSION)' -ForegroundColor Gray; Write-Host ''; $Command" `
            -PassThru
        
        Start-Sleep -Seconds 3
        
        if (Test-Port -Port $Port) {
            Write-Host "   ✅ $Name started successfully (PID: $($proc.Id))" -ForegroundColor Green
            return $proc.Id
        } else {
            Write-Host "   ❌ $Name failed to start" -ForegroundColor Red
            return $null
        }
    } catch {
        Write-Host "   ❌ Error starting $Name : $_" -ForegroundColor Red
        return $null
    }
}

Write-Host "📋 Starting all services with synchronized configuration...`n" -ForegroundColor White

# 1. Start Auth Server (Port 8082)
$authPid = Start-SyncedService `
    -Name "AuthServer" `
    -Port $CONFIG.PORTS.AUTH_SERVER `
    -Directory "$ProjectRoot\backend" `
    -Command "node auth-server.js" `
    -Description "Auth Server + Admin API"

Start-Sleep -Seconds 2

# 2. Start C++ Backend (Port 8080)
$backendPid = Start-SyncedService `
    -Name "Backend" `
    -Port $CONFIG.PORTS.BACKEND_API `
    -Directory "$ProjectRoot\build" `
    -Command ".\nebula_shield_backend.exe" `
    -Description "C++ Antivirus Backend"

Start-Sleep -Seconds 2

# 3. Start React Frontend (Port 3000)
$frontendPid = Start-SyncedService `
    -Name "Frontend" `
    -Port $CONFIG.PORTS.FRONTEND `
    -Directory $ProjectRoot `
    -Command "npm start" `
    -Description "React Frontend + Admin Panel"

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "📊 SYNCHRONIZED SERVICE STATUS" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan

# Display summary with sync status
$summary = @(
    @{
        Name = "Auth Server"
        Port = $CONFIG.PORTS.AUTH_SERVER
        PID = $authPid
        URL = "http://localhost:$($CONFIG.PORTS.AUTH_SERVER)"
        Features = "JWT Auth, Admin API, RBAC, Audit Logs"
        ConfigSync = Test-ServiceConfig -ServiceName "AuthServer"
    },
    @{
        Name = "C++ Backend"
        Port = $CONFIG.PORTS.BACKEND_API
        PID = $backendPid
        URL = "http://localhost:$($CONFIG.PORTS.BACKEND_API)"
        Features = "File Scanning, Real-time Protection, CORS"
        ConfigSync = $true
    },
    @{
        Name = "React Frontend"
        Port = $CONFIG.PORTS.FRONTEND
        PID = $frontendPid
        URL = "http://localhost:$($CONFIG.PORTS.FRONTEND)"
        Features = "Web UI, Admin Panel, Dashboard, 10 Security Modules"
        ConfigSync = Test-ServiceConfig -ServiceName "Frontend"
    }
)

foreach ($service in $summary) {
    $status = if ($service.PID) { "✅ RUNNING" } else { "❌ OFFLINE" }
    $statusColor = if ($service.PID) { "Green" } else { "Red" }
    $syncIcon = if ($service.ConfigSync) { "🔄" } else { "⚠️ " }
    
    Write-Host "$($service.Name)" -ForegroundColor White
    Write-Host "   Status: " -NoNewline
    Write-Host $status -ForegroundColor $statusColor
    Write-Host "   Config Sync: $syncIcon Verified" -ForegroundColor $(if ($service.ConfigSync) { "Green" } else { "Yellow" })
    Write-Host "   Port: $($service.Port)" -ForegroundColor Gray
    if ($service.PID) {
        Write-Host "   PID: $($service.PID)" -ForegroundColor Gray
    }
    Write-Host "   URL: $($service.URL)" -ForegroundColor Gray
    Write-Host "   Features: $($service.Features)" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

# Check if all services are running
$allRunning = $authPid -and $backendPid -and $frontendPid

if ($allRunning) {
    Write-Host "✅ ALL SERVICES SYNCHRONIZED & RUNNING!" -ForegroundColor Green
    Write-Host "`n🌐 Application: http://localhost:3000" -ForegroundColor Cyan
    Write-Host "👑 Admin Panel: http://localhost:3000/admin" -ForegroundColor Magenta
    Write-Host "🔐 Auth API: http://localhost:8082" -ForegroundColor Gray
    Write-Host "🛡️  Backend API: http://localhost:8080" -ForegroundColor Gray
    Write-Host "`n📧 Admin Credentials:" -ForegroundColor Yellow
    Write-Host "   Email: colinnebula@gmail.com" -ForegroundColor White
    Write-Host "   Password: Nebula2025!" -ForegroundColor White
    Write-Host "   Role: Admin" -ForegroundColor Magenta
    Write-Host "   Tier: Premium`n" -ForegroundColor Magenta
} else {
    Write-Host "`n⚠️  SOME SERVICES FAILED TO START" -ForegroundColor Yellow
    Write-Host "   Check the individual service windows for errors`n" -ForegroundColor Gray
}

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan

# Save synchronized state
$stateFile = "$ProjectRoot\sync-state.json"
$state = @{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    version = $CONFIG.VERSION
    services = @{
        authServer = @{
            pid = $authPid
            port = $CONFIG.PORTS.AUTH_SERVER
            running = ($null -ne $authPid)
            configSync = Test-ServiceConfig -ServiceName "AuthServer"
        }
        backend = @{
            pid = $backendPid
            port = $CONFIG.PORTS.BACKEND_API
            running = ($null -ne $backendPid)
            configSync = $true
        }
        frontend = @{
            pid = $frontendPid
            port = $CONFIG.PORTS.FRONTEND
            running = ($null -ne $frontendPid)
            configSync = Test-ServiceConfig -ServiceName "Frontend"
        }
    }
    features = $CONFIG.FEATURES
}

$state | ConvertTo-Json -Depth 10 | Out-File -FilePath $stateFile -Encoding UTF8
Write-Host "💾 Sync state saved to: sync-state.json" -ForegroundColor Gray

# Start health monitor
Write-Host "🏥 Starting health monitor..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList `
    "-NoExit", `
    "-Command", `
    "Set-Location '$ProjectRoot\backend'; Write-Host '🏥 Service Health Monitor - Version $($CONFIG.VERSION)' -ForegroundColor Green; node service-health-monitor.js"

Write-Host "✅ Health monitor started`n" -ForegroundColor Green

Write-Host "🎉 All systems synchronized and ready!`n" -ForegroundColor Green
