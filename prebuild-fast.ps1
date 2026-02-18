# Fast Pre-Build Script for Nebula Shield
# Skips server checks for faster builds

Write-Host ""
Write-Host "========================================"
Write-Host "Fast Pre-Build: Minimal Checks"
Write-Host "========================================"
Write-Host ""

# Quick backend file check only
if (Test-Path "backend/auth-server.js") {
    Write-Host "[✓] Backend server file OK" -ForegroundColor Green
} else {
    Write-Host "[✗] Backend server file missing!" -ForegroundColor Red
    exit 1
}

if (Test-Path "backend/package.json") {
    Write-Host "[✓] Backend package.json OK" -ForegroundColor Green
} else {
    Write-Host "[✗] Backend package.json missing!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================"
Write-Host "Fast Pre-Build Check Complete!"
Write-Host "========================================"
Write-Host ""
