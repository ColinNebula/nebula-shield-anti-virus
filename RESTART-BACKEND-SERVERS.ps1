# Restart Backend Servers with Correct Port Configuration

Write-Host ""
Write-Host "Restarting Backend Servers..." -ForegroundColor Cyan
Write-Host ""

# Stop all Node.js processes
Write-Host "Stopping all Node.js processes..." -ForegroundColor Yellow
Get-Process node -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# Clean up ports
Write-Host "Cleaning up ports 8080 and 8082..." -ForegroundColor Yellow
$ports = @(8080, 8082)
foreach ($port in $ports) {
    try {
        $connections = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Where-Object State -eq 'Listen'
        if ($connections) {
            $processes = $connections | Select-Object -ExpandProperty OwningProcess -Unique
            foreach ($pid in $processes) {
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        # Port not in use
    }
}

Start-Sleep -Seconds 2
Write-Host "Ports cleaned" -ForegroundColor Green
Write-Host ""

# Start Mock Backend API on port 8080
Write-Host "Starting Mock Backend API on port 8080..." -ForegroundColor Cyan
$backendPath = Join-Path $PSScriptRoot "backend"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; Write-Host 'MOCK BACKEND API - Port 8080' -ForegroundColor Cyan; node mock-backend.js" -WindowStyle Normal

Start-Sleep -Seconds 5

# Verify Mock Backend is running
$mockRunning = $false
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/api/status" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
    Write-Host "Mock Backend API running on http://localhost:8080" -ForegroundColor Green
    $mockRunning = $true
} catch {
    Write-Host "Mock Backend API failed to start!" -ForegroundColor Red
}

Write-Host ""

# Start Auth Server on port 8082
Write-Host "Starting Auth Server on port 8082..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; Write-Host 'AUTHENTICATION SERVER - Port 8082' -ForegroundColor Cyan; node auth-server.js" -WindowStyle Normal

Start-Sleep -Seconds 5

# Verify Auth Server is running
$authRunning = $false
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8082/api/auth/status" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
    Write-Host "Auth Server running on http://localhost:8082" -ForegroundColor Green
    $authRunning = $true
} catch {
    Write-Host "Auth Server failed to start!" -ForegroundColor Red
}

Write-Host ""

if ($mockRunning -and $authRunning) {
    Write-Host "Both servers started successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Service URLs:" -ForegroundColor Cyan
    Write-Host "  Mock Backend: http://localhost:8080/api" -ForegroundColor White
    Write-Host "  Auth Server:  http://localhost:8082/api" -ForegroundColor White
    Write-Host ""
    Write-Host "You can now access the app at http://127.0.0.1:3002" -ForegroundColor Yellow
} else {
    Write-Host "Some servers failed to start. Check the server windows for errors." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Press any key to close this window..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
