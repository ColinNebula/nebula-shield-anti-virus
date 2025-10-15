# Nebula Shield - Service Status Check
# Built by Colin Nebula for Nebula3ddev.com

Write-Host ""
Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Nebula Shield - Service Status Check        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check Auth Server (Port 8082)
Write-Host "🔐 Auth Server (Port 8082): " -NoNewline
try {
    $null = Invoke-WebRequest -Uri "http://localhost:8082" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
    Write-Host "✅ RUNNING" -ForegroundColor Green
} catch {
    Write-Host "❌ NOT RUNNING" -ForegroundColor Red
}

# Check Backend Server (Port 8080)
Write-Host "🛡️  Backend Server (Port 8080): " -NoNewline
try {
    $status = Invoke-RestMethod -Uri "http://localhost:8080/api/status" -TimeoutSec 2 -ErrorAction Stop
    if ($status.status -eq "running") {
        Write-Host "✅ RUNNING" -ForegroundColor Green
    } else {
        Write-Host "⚠️  ERROR" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ NOT RUNNING" -ForegroundColor Red
}

# Check Frontend (Port 3001)
Write-Host "🌐 Frontend (Port 3001): " -NoNewline
try {
    $null = Invoke-WebRequest -Uri "http://localhost:3001" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
    Write-Host "✅ RUNNING" -ForegroundColor Green
} catch {
    Write-Host "❌ NOT RUNNING" -ForegroundColor Red
}

Write-Host ""

# Overall Status
$authRunning = $false
$backendRunning = $false
$frontendRunning = $false

try { $null = Invoke-WebRequest -Uri "http://localhost:8082" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop; $authRunning = $true } catch { }
try { $status = Invoke-RestMethod -Uri "http://localhost:8080/api/status" -TimeoutSec 2 -ErrorAction Stop; if ($status.status -eq "running") { $backendRunning = $true } } catch { }
try { $null = Invoke-WebRequest -Uri "http://localhost:3001" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop; $frontendRunning = $true } catch { }

if ($authRunning -and $backendRunning -and $frontendRunning) {
    Write-Host "✅ All services are running!" -ForegroundColor Green
    Write-Host ""
    Write-Host "🌐 Access Nebula Shield at: " -NoNewline
    Write-Host "http://localhost:3001" -ForegroundColor Cyan
} else {
    Write-Host "❌ Some services are not running!" -ForegroundColor Red
    Write-Host ""
    Write-Host "💡 To start all services, run: " -NoNewline -ForegroundColor Yellow
    Write-Host ".\START-ALL-SERVICES.bat" -ForegroundColor White
}

Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
