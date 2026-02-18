# ========================================
# NEBULA SHIELD ANTI-VIRUS
# Stop All Services Script
# ========================================
# Stops all running backend services and cleans up ports
# Version: 2026.01.08

$ErrorActionPreference = "Continue"

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    
    $colors = @{
        "Info" = "Cyan"
        "Success" = "Green"
        "Warning" = "Yellow"
        "Error" = "Red"
    }
    
    $symbols = @{
        "Info" = "ℹ️"
        "Success" = "✓"
        "Warning" = "⚠"
        "Error" = "✗"
    }
    
    Write-Host "$($symbols[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Stop-ProcessOnPort {
    param([int]$Port, [string]$ServiceName)
    
    try {
        $processes = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | 
                     Select-Object -ExpandProperty OwningProcess -Unique
        
        if ($processes) {
            Write-Status "Stopping $ServiceName on port $Port..." "Warning"
            foreach ($pid in $processes) {
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($proc) {
                    Write-Host "   Killing process: $($proc.ProcessName) (PID: $pid)" -ForegroundColor Gray
                    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                }
            }
            Start-Sleep -Seconds 1
            Write-Status "$ServiceName stopped" "Success"
            return $true
        } else {
            Write-Status "$ServiceName not running" "Info"
            return $false
        }
    } catch {
        Write-Status "Error stopping $ServiceName" "Error"
        return $false
    }
}

Clear-Host
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║                                                           ║" -ForegroundColor Red
Write-Host "║              🛑 STOPPING ALL SERVICES 🛑                  ║" -ForegroundColor White
Write-Host "║                                                           ║" -ForegroundColor Red
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""

Write-Status "Shutting down Nebula Shield services..." "Info"
Write-Host ""

# Stop all Node.js processes
Write-Status "Stopping Node.js processes..." "Warning"
Get-Process node -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Stop Electron processes
Write-Status "Stopping Electron processes..." "Warning"
Get-Process electron -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Stop C++ Backend
Write-Status "Stopping C++ Backend..." "Warning"
Get-Process nebula_shield_backend -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Clean up specific ports
Write-Host ""
Write-Status "Cleaning up ports..." "Info"
Stop-ProcessOnPort 3000 "React Dev Server"
Stop-ProcessOnPort 3001 "Mobile Backend"
Stop-ProcessOnPort 3002 "Vite Dev Server"
Stop-ProcessOnPort 5173 "Vite"
Stop-ProcessOnPort 8080 "Mock Backend API"
Stop-ProcessOnPort 8081 "Auth Server (old)"
Stop-ProcessOnPort 8082 "Auth Server"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                                                           ║" -ForegroundColor Green
Write-Host "║               ✓ ALL SERVICES STOPPED ✓                   ║" -ForegroundColor White
Write-Host "║                                                           ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

Write-Host "To restart the application, run:" -ForegroundColor Cyan
Write-Host ".\START-COMPLETE-APP.ps1" -ForegroundColor White
Write-Host ""
Write-Host "Or for development mode:" -ForegroundColor Cyan
Write-Host ".\START-COMPLETE-APP.ps1 -Development" -ForegroundColor White
Write-Host ""

Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
