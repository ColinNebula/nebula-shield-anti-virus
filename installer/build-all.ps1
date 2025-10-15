# One-Click Installer Builder
# Builds everything and creates the final installer in one command

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Nebula Shield - Complete Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Stop"
$InstallerDir = $PSScriptRoot

try {
    # Step 1: Build the installation files
    Write-Host "[1/2] Building installation files..." -ForegroundColor Yellow
    Write-Host ""
    & (Join-Path $InstallerDir "build-installer.ps1")
    
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed!"
    }
    
    Write-Host ""
    Start-Sleep -Seconds 2
    
    # Step 2: Create the installer
    Write-Host "[2/2] Creating installer executable..." -ForegroundColor Yellow
    Write-Host ""
    & (Join-Path $InstallerDir "build-inno-installer.ps1")
    
    if ($LASTEXITCODE -ne 0) {
        throw "Installer creation failed!"
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  All Done!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your installer is ready to distribute!" -ForegroundColor Cyan
    Write-Host ""
    
} catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Build Failed" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
