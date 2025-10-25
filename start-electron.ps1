# Nebula Shield Anti-Virus - Electron App Startup Script
# Ensures backend is running before launching Electron

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   Nebula Shield Electron Startup" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Function to check if a port is in use
function Test-Port {
    param([int]$Port)
    $connection = Test-NetConnection -ComputerName localhost -Port $Port -WarningAction SilentlyContinue -InformationLevel Quiet
    return $connection
}

# Function to wait for server to be ready
function Wait-ForServer {
    param(
        [string]$Name,
        [int]$Port,
        [int]$MaxWaitSeconds = 30
    )
    
    Write-Host "Waiting for $Name to be ready on port $Port..." -ForegroundColor Yellow
    $waited = 0
    
    while ($waited -lt $MaxWaitSeconds) {
        if (Test-Port -Port $Port) {
            Write-Host "✅ $Name is ready!" -ForegroundColor Green
            return $true
        }
        Start-Sleep -Seconds 1
        $waited++
        Write-Host "." -NoNewline -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "❌ $Name failed to start within $MaxWaitSeconds seconds" -ForegroundColor Red
    return $false
}

# Check if backend is running
Write-Host "Checking backend server..." -ForegroundColor Cyan

if (Test-Port -Port 8080) {
    Write-Host "✅ Backend server is running on port 8080" -ForegroundColor Green
} else {
    Write-Host "⚠️  Backend server not running. Starting..." -ForegroundColor Yellow
    
    # Start backend in a new minimized window
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; node mock-backend-secure.js" -WindowStyle Minimized
    
    # Wait for backend to be ready
    if (-not (Wait-ForServer -Name "Backend" -Port 8080)) {
        Write-Host ""
        Write-Host "❌ Failed to start backend server" -ForegroundColor Red
        Write-Host "Cannot launch Electron without backend" -ForegroundColor Yellow
        pause
        exit 1
    }
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "   Launching Electron App..." -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""

# Launch Electron in development mode
npm run electron:dev
