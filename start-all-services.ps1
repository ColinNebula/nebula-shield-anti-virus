# Nebula Shield - Quick Start Script
# Starts all services needed for the application

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  NEBULA SHIELD - Starting Services" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$projectRoot = "Z:\Directory\projects\nebula-shield-anti-virus"
Set-Location $projectRoot

# Stop existing processes
Write-Host "Stopping existing services..." -ForegroundColor Yellow
Get-Process -Name "node" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process -Name "nebula_shield_backend" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Write-Host "Done.`n" -ForegroundColor Green

# Start Auth Server
Write-Host "Starting Auth Server (Port 8081)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$projectRoot'; Write-Host 'AUTH SERVER' -ForegroundColor Cyan; node backend/auth-server.js"
Start-Sleep -Seconds 5

# Verify Auth Server
try {
    Invoke-WebRequest -Uri "http://localhost:8081/" -TimeoutSec 2 -ErrorAction Stop | Out-Null
    Write-Host "Auth Server: RUNNING`n" -ForegroundColor Green
} catch {
    if ($_.Exception.Response.StatusCode) {
        Write-Host "Auth Server: RUNNING`n" -ForegroundColor Green
    } else {
        Write-Host "Auth Server: FAILED`n" -ForegroundColor Red
    }
}

# Start C++ Backend
Write-Host "Starting C++ Backend (Port 8080)..." -ForegroundColor Yellow
$backendExe = "$projectRoot\backend\build\bin\Release\nebula_shield_backend.exe"
if (Test-Path $backendExe) {
    Start-Process -FilePath $backendExe -WorkingDirectory $projectRoot -WindowStyle Minimized
    Start-Sleep -Seconds 2
    Write-Host "C++ Backend: STARTED`n" -ForegroundColor Green
} else {
    Write-Host "C++ Backend: NOT FOUND (Optional)`n" -ForegroundColor Yellow
}

# Start React Frontend
Write-Host "Starting React Frontend (Port 3000)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$projectRoot'; Write-Host 'REACT FRONTEND' -ForegroundColor Cyan; npm start"
Start-Sleep -Seconds 3
Write-Host "React: STARTING (will open browser)`n" -ForegroundColor Green

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ALL SERVICES STARTED!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Login: colinnebula@gmail.com" -ForegroundColor White
Write-Host "Password: Nebula2025!`n" -ForegroundColor White

Write-Host "Press any key to close this window..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
