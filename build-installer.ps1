# Nebula Shield Anti-Virus - Installer Build Script
# This script builds a complete installer package for distribution

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Nebula Shield Anti-Virus - Build Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Clean previous builds
Write-Host "[1/5] Cleaning previous builds..." -ForegroundColor Yellow
if (Test-Path "dist") {
    Remove-Item -Recurse -Force "dist"
    Write-Host "  Done - Cleaned dist folder" -ForegroundColor Green
}
if (Test-Path "build") {
    Remove-Item -Recurse -Force "build"
    Write-Host "  Done - Cleaned build folder" -ForegroundColor Green
}

# Step 2: Install/Update dependencies
Write-Host ""
Write-Host "[2/6] Checking dependencies..." -ForegroundColor Yellow
npm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Error - Failed to install dependencies" -ForegroundColor Red
    exit 1
}
Write-Host "  Done - Dependencies ready" -ForegroundColor Green

# Step 3: Prepare backend
Write-Host ""
Write-Host "[3/6] Preparing backend..." -ForegroundColor Yellow
powershell -ExecutionPolicy Bypass -File ./prepare-backend.ps1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Error - Backend preparation failed" -ForegroundColor Red
    exit 1
}
Write-Host "  Done - Backend ready" -ForegroundColor Green

# Step 4: Build the application
Write-Host ""
Write-Host "[4/6] Building application..." -ForegroundColor Yellow
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Error - Build failed" -ForegroundColor Red
    exit 1
}
Write-Host "  Done - Application built successfully"

# Step 5: Create installer package
Write-Host ""
Write-Host "[5/6] Creating installer packages..." -ForegroundColor Yellow
Write-Host "  This may take several minutes..." -ForegroundColor Gray
npm run electron:build:win
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Error - Installer creation failed" -ForegroundColor Red
    exit 1
}
Write-Host "  Done - Installer packages created" -ForegroundColor Green

# Step 6: Show results
Write-Host ""
Write-Host "[6/6] Build Summary" -ForegroundColor Yellow
Write-Host ""

$installerFiles = Get-ChildItem -Path "dist" -Filter "*.exe" -Recurse
if ($installerFiles.Count -eq 0) {
    Write-Host "  Error - No installer files found!" -ForegroundColor Red
    exit 1
}

Write-Host "  Installer packages created:" -ForegroundColor Green
foreach ($file in $installerFiles) {
    $sizeInMB = [math]::Round($file.Length / 1MB, 2)
    $fileName = $file.Name
    Write-Host "    * $fileName - $sizeInMB MB" -ForegroundColor Cyan
    $filePath = $file.FullName
    Write-Host "      Location: $filePath" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "BUILD COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Your installer packages are ready in the dist folder." -ForegroundColor White
Write-Host ""
Write-Host "Installation Types Created:" -ForegroundColor Yellow
Write-Host "  1. NSIS Installer - Full featured installer with custom options" -ForegroundColor White
Write-Host "  2. Portable - No installation required, run directly" -ForegroundColor White
Write-Host ""
Write-Host "You can now distribute these files to install on other computers." -ForegroundColor White
Write-Host ""

# Open dist folder
$openFolder = Read-Host "Open dist folder? (Y/N)"
if ($openFolder -eq "Y" -or $openFolder -eq "y") {
    $distPath = "dist"
    Invoke-Item $distPath
}
