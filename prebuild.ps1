#!/usr/bin/env pwsh
# Pre-build script to ensure all dependencies are installed

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Pre-Build: Installing Dependencies" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if backend node_modules exists
Write-Host "[1/3] Checking backend dependencies..." -ForegroundColor Yellow
if (-not (Test-Path "backend/node_modules")) {
    Write-Host "Backend dependencies not found. Installing..." -ForegroundColor Yellow
    Push-Location backend
    npm install --production
    Pop-Location
    Write-Host "Backend dependencies installed!" -ForegroundColor Green
} else {
    Write-Host "Backend dependencies OK" -ForegroundColor Green
}

# Check if backend package.json exists
Write-Host "`n[2/3] Verifying backend package.json..." -ForegroundColor Yellow
if (-not (Test-Path "backend/package.json")) {
    Write-Host "ERROR: backend/package.json not found!" -ForegroundColor Red
    exit 1
}
Write-Host "backend/package.json OK" -ForegroundColor Green

# Check if auth-server.js exists
Write-Host "`n[3/3] Verifying backend server file..." -ForegroundColor Yellow
if (-not (Test-Path "backend/auth-server.js")) {
    Write-Host "ERROR: backend/auth-server.js not found!" -ForegroundColor Red
    exit 1
}
Write-Host "backend/auth-server.js OK" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Pre-Build Check Complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan
