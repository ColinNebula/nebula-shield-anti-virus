# Nebula Shield Electron Production Builder
# This script builds the React app and packages it as an Electron desktop application

param(
    [string]$Platform = "win"
)

Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "   Nebula Shield Production Builder" -ForegroundColor Cyan
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

Write-Host "[INFO] Building Nebula Shield for platform: $Platform" -ForegroundColor Green
Write-Host ""

# Clean previous builds
if (Test-Path "dist") {
    Write-Host "[INFO] Cleaning previous build..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force dist
}

# Build based on platform
switch ($Platform.ToLower()) {
    "win" {
        Write-Host "[INFO] Building for Windows..." -ForegroundColor Cyan
        npm run dist:win
    }
    "mac" {
        Write-Host "[INFO] Building for macOS..." -ForegroundColor Cyan
        npm run dist:mac
    }
    "linux" {
        Write-Host "[INFO] Building for Linux..." -ForegroundColor Cyan
        npm run dist:linux
    }
    "all" {
        Write-Host "[INFO] Building for all platforms..." -ForegroundColor Cyan
        npm run dist
    }
    default {
        Write-Host "[ERROR] Invalid platform: $Platform" -ForegroundColor Red
        Write-Host "[INFO] Valid options: win, mac, linux, all" -ForegroundColor Yellow
        exit 1
    }
}

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "===========================================" -ForegroundColor Green
    Write-Host "   Build Complete!" -ForegroundColor Green
    Write-Host "===========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "[INFO] Installer files are in the 'dist' folder" -ForegroundColor Cyan
    
    if (Test-Path "dist") {
        Write-Host ""
        Write-Host "Output files:" -ForegroundColor Yellow
        Get-ChildItem -Path "dist" -File | ForEach-Object {
            $size = "{0:N2} MB" -f ($_.Length / 1MB)
            Write-Host "  - $($_.Name) ($size)" -ForegroundColor White
        }
    }
} else {
    Write-Host ""
    Write-Host "[ERROR] Build failed!" -ForegroundColor Red
    exit 1
}
