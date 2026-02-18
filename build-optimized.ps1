# Nebula Shield - Optimized Build Script
# Fastest build with minimal overhead

param(
    [switch]$SkipClean = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Nebula Shield - Optimized Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Clean dist folder if not skipped
if (-not $SkipClean) {
    if (Test-Path "dist") {
        Write-Host "[1/4] Cleaning dist folder..." -ForegroundColor Yellow
        Remove-Item -Path "dist" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "      [OK] Dist folder cleaned" -ForegroundColor Green
    }
} else {
    Write-Host "[1/4] Skipping clean (SkipClean flag)" -ForegroundColor Gray
}

# Quick validation
Write-Host "[2/4] Validating backend files..." -ForegroundColor Yellow
if (-not (Test-Path "backend/auth-server.js")) {
    Write-Host "      [ERROR] Backend server missing!" -ForegroundColor Red
    exit 1
}
Write-Host "      [OK] Backend validated" -ForegroundColor Green

# Build frontend with optimizations
Write-Host "[3/4] Building frontend (optimized)..." -ForegroundColor Yellow
$env:NODE_ENV = "production"
$buildStart = Get-Date

if ($Verbose) {
    & npm run build 2>&1
} else {
    & npm run build 2>&1 | Out-Null
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "      [ERROR] Frontend build failed!" -ForegroundColor Red
    exit 1
}

$buildTime = [math]::Round(((Get-Date) - $buildStart).TotalSeconds, 1)
Write-Host "      [OK] Frontend built in $buildTime seconds" -ForegroundColor Green

# Package with electron-builder
Write-Host "[4/4] Packaging with electron-builder..." -ForegroundColor Yellow
$packageStart = Get-Date

if ($Verbose) {
    & npx electron-builder --win portable 2>&1
} else {
    & npx electron-builder --win portable 2>&1 | Out-Null
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "      [ERROR] Packaging failed!" -ForegroundColor Red
    exit 1
}

$packageTime = [math]::Round(((Get-Date) - $packageStart).TotalSeconds, 1)
Write-Host "      [OK] Packaged in $packageTime seconds" -ForegroundColor Green

# Summary
$totalTime = $buildTime + $packageTime
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Total Time: $totalTime seconds" -ForegroundColor White
Write-Host "  Build Time: $buildTime seconds" -ForegroundColor White
Write-Host "  Package Time: $packageTime seconds" -ForegroundColor White

# Show output file
if (Test-Path "dist/*.exe") {
    $outputFile = Get-ChildItem -Path "dist" -Filter "*.exe" | Select-Object -First 1
    $sizeMB = [math]::Round($outputFile.Length / 1MB, 2)
    Write-Host "  Output: $($outputFile.Name) ($sizeMB MB)" -ForegroundColor White
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
