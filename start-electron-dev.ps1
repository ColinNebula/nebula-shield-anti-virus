# Nebula Shield Electron Development Launcher
# This script starts both the React dev server and Electron app

Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "   Nebula Shield Electron Dev Mode" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host ""

# Check if node_modules exists
if (-Not (Test-Path "node_modules")) {
    Write-Host "[ERROR] node_modules not found. Running npm install..." -ForegroundColor Red
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] npm install failed!" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[INFO] Starting Nebula Shield in Electron development mode..." -ForegroundColor Green
Write-Host "[INFO] This will:" -ForegroundColor Yellow
Write-Host "  1. Start the React development server on port 3001" -ForegroundColor Yellow
Write-Host "  2. Wait for the server to be ready" -ForegroundColor Yellow
Write-Host "  3. Launch the Electron desktop application" -ForegroundColor Yellow
Write-Host ""
Write-Host "[INFO] Press Ctrl+C to stop all processes" -ForegroundColor Yellow
Write-Host ""

# Run the electron:dev script
npm run electron:dev
