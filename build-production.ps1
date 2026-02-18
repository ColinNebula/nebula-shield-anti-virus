# Production Build Script - Includes Backend Dependencies
# This creates a standalone executable that doesn't require npm/Node.js on user's system

param(
    [switch]$Clean = $false
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Nebula Shield - Production Build" -ForegroundColor Cyan
Write-Host " (Includes backend dependencies)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Clean if requested
if ($Clean -and (Test-Path "dist")) {
    Write-Host "[1/5] Cleaning dist folder..." -ForegroundColor Yellow
    Remove-Item -Path "dist" -Recurse -Force
    Write-Host "      [OK] Cleaned" -ForegroundColor Green
} else {
    Write-Host "[1/5] Skipping clean" -ForegroundColor Gray
}

# Install backend dependencies
Write-Host "[2/5] Installing backend dependencies..." -ForegroundColor Yellow
Push-Location backend
try {
    & npm install --production --no-optional 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "      [OK] Backend dependencies installed" -ForegroundColor Green
    } else {
        Write-Host "      [ERROR] Failed to install backend dependencies" -ForegroundColor Red
        Pop-Location
        exit 1
    }
} finally {
    Pop-Location
}

# Validate backend
Write-Host "[3/5] Validating backend..." -ForegroundColor Yellow
if (Test-Path "backend/node_modules") {
    $backendSize = (Get-ChildItem -Path "backend/node_modules" -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
    Write-Host "      [OK] Backend ready ($([math]::Round($backendSize, 1)) MB)" -ForegroundColor Green
} else {
    Write-Host "      [ERROR] Backend node_modules missing!" -ForegroundColor Red
    exit 1
}

# Build frontend
Write-Host "[4/5] Building frontend..." -ForegroundColor Yellow
$env:NODE_ENV = "production"
& npm run build 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "      [OK] Frontend built" -ForegroundColor Green
} else {
    Write-Host "      [ERROR] Frontend build failed" -ForegroundColor Red
    exit 1
}

# Package with electron-builder using production config
Write-Host "[5/5] Packaging (this may take a few minutes)..." -ForegroundColor Yellow
& npx electron-builder --config electron-builder.production.json --win 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "      [OK] Packaged successfully" -ForegroundColor Green
} else {
    Write-Host "      [ERROR] Packaging failed" -ForegroundColor Red
    exit 1
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Production Build Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

if (Test-Path "dist/*.exe") {
    Get-ChildItem -Path "dist" -Filter "*.exe" | ForEach-Object {
        $sizeMB = [math]::Round($_.Length / 1MB, 2)
        Write-Host "  Output: $($_.Name) ($sizeMB MB)" -ForegroundColor White
    }
}

Write-Host ""
Write-Host "This build includes all dependencies and works on any Windows PC" -ForegroundColor Green
Write-Host "No Node.js or npm installation required on user's system" -ForegroundColor Green
Write-Host ""
