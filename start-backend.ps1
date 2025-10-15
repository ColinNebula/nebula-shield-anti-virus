# Start Nebula Shield C++ Backend Server

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Starting Nebula Shield Backend Server" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$exePath = "backend\build\bin\Release\nebula_shield_backend.exe"

if (-not (Test-Path $exePath)) {
    Write-Host "✗ Backend executable not found!" -ForegroundColor Red
    Write-Host "  Expected location: $exePath`n" -ForegroundColor Gray
    Write-Host "Build the backend first:" -ForegroundColor Yellow
    Write-Host "  .\build-backend.ps1`n" -ForegroundColor White
    exit 1
}

# Check if port 8080 is in use
Write-Host "Checking port 8080..." -ForegroundColor Gray
$portInUse = Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue

if ($portInUse) {
    Write-Host "⚠ Port 8080 is already in use" -ForegroundColor Yellow
    Write-Host "`nStop the process using port 8080:" -ForegroundColor Yellow
    Get-Process -Id $portInUse.OwningProcess | Format-Table Id, ProcessName, StartTime -AutoSize
    
    $response = Read-Host "`nKill this process? (y/n)"
    if ($response -eq 'y') {
        Stop-Process -Id $portInUse.OwningProcess -Force
        Write-Host "✓ Process stopped`n" -ForegroundColor Green
        Start-Sleep -Seconds 2
    } else {
        Write-Host "Exiting...`n" -ForegroundColor Gray
        exit 0
    }
}

# Start the backend
Write-Host "Starting backend server..." -ForegroundColor Green
Write-Host "  Executable: $exePath" -ForegroundColor Gray
Write-Host "  Server will run on: http://localhost:8080`n" -ForegroundColor Gray
Write-Host "Press Ctrl+C to stop the server`n" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

try {
    & $exePath
} catch {
    Write-Host "`n✗ Server stopped with error: $_" -ForegroundColor Red
    exit 1
}
