# Prepare Backend for Standalone Distribution
# This script prepares the backend to be bundled with the installer

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Preparing Backend for Standalone Distribution" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$backendPath = "backend"

if (-not (Test-Path $backendPath)) {
    Write-Host "Error: Backend directory not found!" -ForegroundColor Red
    exit 1
}

# Check if backend has package.json
if (-not (Test-Path "$backendPath\package.json")) {
    Write-Host "Error: Backend package.json not found!" -ForegroundColor Red
    exit 1
}

Push-Location $backendPath

try {
    # Check if dependencies already exist
    if (Test-Path "node_modules") {
        Write-Host "Backend dependencies already installed, skipping..." -ForegroundColor Green
        $size = (Get-ChildItem node_modules -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Host "Backend node_modules size: $([math]::Round($size, 2)) MB" -ForegroundColor Cyan
    } else {
        Write-Host "Installing backend dependencies..." -ForegroundColor Yellow
        # Install production dependencies only
        npm ci --only=production --silent
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Backend dependencies installed successfully!" -ForegroundColor Green
            
            # Show backend node_modules size
            if (Test-Path "node_modules") {
                $size = (Get-ChildItem node_modules -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
                Write-Host "Backend node_modules size: $([math]::Round($size, 2)) MB" -ForegroundColor Cyan
            }
        } else {
            Write-Host "Failed to install backend dependencies!" -ForegroundColor Red
            Pop-Location
            exit 1
        }
    }
    
    # Create database directories
    Write-Host "Setting up data directories..." -ForegroundColor Yellow
    $dataDirectories = @("data", "data/quarantine", "data/logs", "data/virus-definitions", "data/backups")
    foreach ($dir in $dataDirectories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "Created directory: $dir" -ForegroundColor Green
        }
    }
    
    # Create default configuration
    Write-Host "Creating default configuration..." -ForegroundColor Yellow
    $configTemplate = @{
        "server" = @{
            "port" = 8080
            "host" = "localhost"
            "environment" = "production"
        }
        "security" = @{
            "enableSSL" = $false
            "enableCORS" = $true
            "rateLimit" = $true
        }
        "database" = @{
            "type" = "sqlite"
            "path" = "./data/nebula-shield.db"
        }
        "antivirus" = @{
            "realTimeProtection" = $true
            "autoQuarantine" = $true
            "scanDepth" = "deep"
            "updateFrequency" = "daily"
        }
        "firewall" = @{
            "enabled" = $true
            "logBlocked" = $true
            "blockMaliciousIPs" = $true
        }
        "logging" = @{
            "level" = "info"
            "maxFileSize" = "10MB"
            "maxFiles" = 5
        }
    }
    
    $configPath = "data/config.json"
    $configTemplate | ConvertTo-Json -Depth 10 | Out-File $configPath -Encoding UTF8
    Write-Host "Created default configuration: $configPath" -ForegroundColor Green
    
    # Create startup scripts
    Write-Host "Creating startup scripts..." -ForegroundColor Yellow
    
    $batchScript = @'
@echo off
title Nebula Shield Backend Server
echo Starting Nebula Shield Backend Server...
echo.
node auth-server.js
pause
'@
    $batchScript | Out-File "start-backend.bat" -Encoding ASCII
    Write-Host "Created start-backend.bat" -ForegroundColor Green
    
    $powershellScript = @'
# Nebula Shield Backend Startup Script
Write-Host "Starting Nebula Shield Backend Server..." -ForegroundColor Cyan
try {
    node auth-server.js
} catch {
    Write-Host "Error starting backend: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
}
'@
    $powershellScript | Out-File "start-backend.ps1" -Encoding UTF8
    Write-Host "Created start-backend.ps1" -ForegroundColor Green
    
    # Create version info file
    Write-Host "Creating version info..." -ForegroundColor Yellow
    $versionInfo = @{
        "version" = "1.0.0"
        "buildDate" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        "platform" = "win32"
        "architecture" = "x64"
        "nodeVersion" = (node --version)
    }
    
    $versionInfo | ConvertTo-Json -Depth 10 | Out-File "version-info.json" -Encoding UTF8
    Write-Host "Created version info file" -ForegroundColor Green
    
} catch {
    Write-Host "Error preparing backend: $_" -ForegroundColor Red
    Pop-Location
    exit 1
}

Pop-Location

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Backend ready for standalone packaging!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
