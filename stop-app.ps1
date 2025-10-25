# Nebula Shield Anti-Virus - Stop All Services
# This script stops all running backend services and the app

Write-Host "`n🛑 Stopping Nebula Shield Anti-Virus..." -ForegroundColor Red
Write-Host "=" * 60 -ForegroundColor Gray

$ErrorActionPreference = "Continue"

# Function to kill process on port
function Stop-ProcessOnPort {
    param(
        [int]$Port,
        [string]$ServiceName
    )
    
    try {
        $processes = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | 
                     Select-Object -ExpandProperty OwningProcess -Unique
        
        if ($processes) {
            Write-Host "   Stopping $ServiceName on port $Port..." -ForegroundColor Yellow
            foreach ($pid in $processes) {
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            }
            Write-Host "   ✓ $ServiceName stopped" -ForegroundColor Green
            return $true
        } else {
            Write-Host "   $ServiceName not running on port $Port" -ForegroundColor Gray
            return $false
        }
    } catch {
        Write-Host "   Error stopping $ServiceName" -ForegroundColor Yellow
        return $false
    }
}

Write-Host "`nStopping backend services..." -ForegroundColor Cyan

# Stop Mock Backend (port 8080)
Stop-ProcessOnPort 8080 "Mock Backend Server"

# Stop Auth Server (port 8082)
Stop-ProcessOnPort 8082 "Auth Server"

# Stop any Electron instances
Write-Host "`nStopping Electron app..." -ForegroundColor Cyan
try {
    $electronProcesses = Get-Process | Where-Object { $_.ProcessName -like "*Nebula*Shield*" -or $_.ProcessName -eq "electron" }
    if ($electronProcesses) {
        $electronProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "   ✓ Electron app stopped" -ForegroundColor Green
    } else {
        Write-Host "   Electron app not running" -ForegroundColor Gray
    }
} catch {
    Write-Host "   Error stopping Electron app" -ForegroundColor Yellow
}

Write-Host "`n" + "=" * 60 -ForegroundColor Gray
Write-Host "✅ All services stopped!" -ForegroundColor Green
Write-Host "`nPress any key to close this window..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
