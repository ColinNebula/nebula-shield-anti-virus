# Nebula Shield - Service Diagnostic & Restart Script
# Run this as Administrator if you're having issues

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Nebula Shield - Service Diagnostics" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "⚠️  WARNING: Not running as Administrator" -ForegroundColor Yellow
    Write-Host "   Some operations may fail without admin rights" -ForegroundColor Gray
    Write-Host ""
}

$InstallPath = "C:\Program Files\Nebula Shield"

# Check if installed
if (!(Test-Path $InstallPath)) {
    Write-Host "❌ ERROR: Nebula Shield not found at $InstallPath" -ForegroundColor Red
    Write-Host "   Please install Nebula Shield first." -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "✅ Installation found at: $InstallPath" -ForegroundColor Green
Write-Host ""

# Check services
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Service Status" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$Services = @(
    @{Name="NebulaShieldBackend"; Port=8080; Description="C++ Antivirus Engine"},
    @{Name="NebulaShieldAuth"; Port=8081; Description="Authentication Server"},
    @{Name="NebulaShieldFrontend"; Port=3000; Description="Web Interface"}
)

$AllRunning = $true
foreach ($Svc in $Services) {
    $Service = Get-Service -Name $Svc.Name -ErrorAction SilentlyContinue
    Write-Host "$($Svc.Name) (Port $($Svc.Port)) - $($Svc.Description)" -ForegroundColor White
    if ($Service) {
        if ($Service.Status -eq "Running") {
            Write-Host "  ✅ Status: Running" -ForegroundColor Green
        } else {
            Write-Host "  ⚠️  Status: $($Service.Status)" -ForegroundColor Yellow
            $AllRunning = $false
        }
    } else {
        Write-Host "  ❌ Status: NOT INSTALLED" -ForegroundColor Red
        $AllRunning = $false
    }
    Write-Host ""
}

# Test endpoints
if ($AllRunning) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Endpoint Tests" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Test Backend
    Write-Host "Testing Backend (http://localhost:8080)..." -NoNewline
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8080/api/status" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        Write-Host " ✅" -ForegroundColor Green
    } catch {
        Write-Host " ❌ Failed" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
    }
    
    # Test Auth Server
    Write-Host "Testing Auth Server (http://localhost:8081)..." -NoNewline
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8081/api/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        Write-Host " ✅" -ForegroundColor Green
    } catch {
        Write-Host " ❌ Failed" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
    }
    
    # Test Frontend
    Write-Host "Testing Frontend (http://localhost:3000)..." -NoNewline
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        Write-Host " ✅" -ForegroundColor Green
    } catch {
        Write-Host " ❌ Failed" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
    }
    Write-Host ""
}

# Check logs
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Recent Log Errors" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$LogFiles = @(
    "backend-service.log",
    "backend-error.log",
    "auth-service.log",
    "auth-error.log",
    "frontend-service.log",
    "frontend-error.log"
)

foreach ($LogFile in $LogFiles) {
    $LogPath = Join-Path $InstallPath "data\logs\$LogFile"
    if (Test-Path $LogPath) {
        $LastLines = Get-Content $LogPath -Tail 5 -ErrorAction SilentlyContinue
        if ($LastLines -and ($LastLines -match "error|fail|exception")) {
            Write-Host "⚠️  $LogFile (last 5 lines):" -ForegroundColor Yellow
            $LastLines | ForEach-Object { Write-Host "   $_" -ForegroundColor Gray }
            Write-Host ""
        }
    }
}

# Action menu
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Actions" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (!$AllRunning) {
    Write-Host "Some services are not running or installed." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Options:" -ForegroundColor White
    Write-Host "  [1] Install all services (requires admin)" -ForegroundColor Cyan
    Write-Host "  [2] Start all services" -ForegroundColor Cyan
    Write-Host "  [3] Restart all services" -ForegroundColor Cyan
    Write-Host "  [4] View full logs" -ForegroundColor Cyan
    Write-Host "  [5] Open app in browser" -ForegroundColor Cyan
    Write-Host "  [Q] Quit" -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "Select option"
    
    switch ($choice) {
        "1" {
            if (!$isAdmin) {
                Write-Host ""
                Write-Host "Restarting as Administrator..." -ForegroundColor Yellow
                Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$InstallPath'; .\install-services.bat" -Verb RunAs
            } else {
                & "$InstallPath\install-services.bat"
            }
        }
        "2" {
            Write-Host ""
            Write-Host "Starting services..." -ForegroundColor Yellow
            foreach ($Svc in $Services) {
                & "$InstallPath\nssm.exe" start $Svc.Name
            }
            Write-Host "✅ Services started" -ForegroundColor Green
        }
        "3" {
            Write-Host ""
            Write-Host "Restarting services..." -ForegroundColor Yellow
            foreach ($Svc in $Services) {
                & "$InstallPath\nssm.exe" restart $Svc.Name
            }
            Write-Host "✅ Services restarted" -ForegroundColor Green
        }
        "4" {
            Write-Host ""
            Write-Host "Opening logs directory..." -ForegroundColor Yellow
            Start-Process "$InstallPath\data\logs"
        }
        "5" {
            Write-Host ""
            Write-Host "Opening browser..." -ForegroundColor Yellow
            Start-Process "http://localhost:3000"
        }
    }
} else {
    Write-Host "✅ All services are running!" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can access Nebula Shield at:" -ForegroundColor Cyan
    Write-Host "  http://localhost:3000" -ForegroundColor White
    Write-Host ""
    
    $choice = Read-Host "Open in browser? (Y/N)"
    if ($choice -eq 'Y' -or $choice -eq 'y') {
        Start-Process "http://localhost:3000"
    }
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
