#!/usr/bin/env pwsh
# Start all Nebula Shield servers

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host " Nebula Shield - Starting All Servers" -ForegroundColor Cyan
Write-Host "================================================`n" -ForegroundColor Cyan

# Check if Node.js is installed
$nodeExists = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeExists) {
    Write-Host "ERROR: Node.js is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

# Check if backend is already running
Write-Host "Checking for existing servers..." -ForegroundColor Yellow
$backendRunning = $false
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/api/health" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
    if ($response.StatusCode -eq 200) {
        $backendRunning = $true
        Write-Host "✅ Backend server already running on port 8080" -ForegroundColor Green
    }
} catch {
    # Backend not running, we'll start it
}

# Start backend if not running
if (-not $backendRunning) {
    Write-Host "`n[1/2] Starting Backend Server on port 8080..." -ForegroundColor Cyan
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host 'Nebula Shield - Backend Server' -ForegroundColor Green; node backend/auth-server.js"
    Start-Sleep -Seconds 3
}

# Start frontend dev server
Write-Host "[2/2] Starting Frontend Dev Server on port 3002..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host 'Nebula Shield - Frontend Dev Server' -ForegroundColor Green; npm run dev"

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host " Servers Starting..." -ForegroundColor Cyan
Write-Host "================================================`n" -ForegroundColor Cyan
Write-Host "Backend Server:  " -NoNewline -ForegroundColor White
Write-Host "http://localhost:8080" -ForegroundColor Green
Write-Host "Frontend Server: " -NoNewline -ForegroundColor White
Write-Host "http://localhost:3002" -ForegroundColor Green
Write-Host "`nClose the terminal windows to stop the servers" -ForegroundColor Yellow
Write-Host "================================================`n" -ForegroundColor Cyan

# Wait for servers to start and verify
Write-Host "Waiting for servers to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host "`nVerifying servers..." -ForegroundColor Cyan
& "$PSScriptRoot/check-servers.ps1"
