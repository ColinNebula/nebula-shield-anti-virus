# Standalone Package Verification Script
# This script verifies that the application is properly configured for standalone deployment

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Standalone Package Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorCount = 0
$WarningCount = 0

# Function to check file/directory
function Check-Path {
    param($Path, $Name, $Required = $true)
    
    if (Test-Path $Path) {
        Write-Host "OK $Name exists" -ForegroundColor Green
        return $true
    } else {
        if ($Required) {
            Write-Host "ERR $Name missing: $Path" -ForegroundColor Red
            $script:ErrorCount++
        } else {
            Write-Host "WARN $Name missing (optional): $Path" -ForegroundColor Yellow
            $script:WarningCount++
        }
        return $false
    }
}

# 1. Check Backend Files
Write-Host "[1/6] Checking Backend Files..." -ForegroundColor Yellow
Check-Path "backend/auth-server.js" "Backend main file"
Check-Path "backend/package.json" "Backend package.json"
Check-Path "backend/node_modules" "Backend dependencies"
Check-Path "backend/data" "Backend data directory"
Write-Host ""

# 2. Check Frontend Build
Write-Host "[2/6] Checking Frontend Build..." -ForegroundColor Yellow
Check-Path "build" "Build directory"
Check-Path "build/index.html" "Build index.html"
if (Test-Path "build") {
    $buildFiles = Get-ChildItem -Path "build" -Recurse -File
    Write-Host "  Build contains $($buildFiles.Count) files" -ForegroundColor Cyan
}
Write-Host ""

# 3. Check Electron Configuration
Write-Host "[3/6] Checking Electron Configuration..." -ForegroundColor Yellow
Check-Path "public/electron.js" "Electron main process"
Check-Path "public/preload.js" "Electron preload script"
Check-Path "electron-builder.json" "Electron builder config"

# Verify electron-builder.json has extraResources
if (Test-Path "electron-builder.json") {
    $builderConfig = Get-Content "electron-builder.json" | ConvertFrom-Json
    if ($builderConfig.extraResources) {
        Write-Host "OK extraResources configured" -ForegroundColor Green
        
        # Check if backend is in extraResources
        $hasBackend = $false
        foreach ($resource in $builderConfig.extraResources) {
            if ($resource.from -eq "backend") {
                $hasBackend = $true
                break
            }
        }
        
        if ($hasBackend) {
            Write-Host "OK Backend is in extraResources" -ForegroundColor Green
        } else {
            Write-Host "ERR Backend not found in extraResources" -ForegroundColor Red
            $ErrorCount++
        }
    } else {
        Write-Host "ERR extraResources not configured" -ForegroundColor Red
        $ErrorCount++
    }
}
Write-Host ""

# 4. Check Icons and Resources
Write-Host "[4/6] Checking Icons and Resources..." -ForegroundColor Yellow
Check-Path "build-resources/icon.ico" "Windows icon (.ico)"
Check-Path "build-resources/icon.png" "Cross-platform icon (.png)"
Check-Path "public/icon.png" "Public icon" $false
Check-Path "public/favicon.ico" "Favicon" $false
Write-Host ""

# 5. Check Node.js and Dependencies
Write-Host "[5/6] Checking Node.js Environment..." -ForegroundColor Yellow
try {
    $nodeVersion = node --version
    Write-Host "OK Node.js installed: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "ERR Node.js not found in PATH" -ForegroundColor Red
    $ErrorCount++
}

try {
    $npmVersion = npm --version
    Write-Host "OK npm installed: $npmVersion" -ForegroundColor Green
} catch {
    Write-Host "ERR npm not found in PATH" -ForegroundColor Red
    $ErrorCount++
}

# Check if node_modules exists
if (Test-Path "node_modules") {
    $nodeModulesCount = (Get-ChildItem -Path "node_modules" -Directory).Count
    Write-Host "OK Root node_modules exists ($nodeModulesCount packages)" -ForegroundColor Green
} else {
    Write-Host "ERR Root node_modules missing" -ForegroundColor Red
    $ErrorCount++
}
Write-Host ""

# 6. Check Backend Dependencies
Write-Host "[6/6] Checking Backend Dependencies..." -ForegroundColor Yellow
if (Test-Path "backend/node_modules") {
    $backendModules = (Get-ChildItem -Path "backend/node_modules" -Directory).Count
    Write-Host "OK Backend node_modules exists ($backendModules packages)" -ForegroundColor Green
    
    # Check critical backend modules
    $criticalModules = @("express", "sqlite3", "bcryptjs", "cors", "jsonwebtoken")
    foreach ($module in $criticalModules) {
        Check-Path "backend/node_modules/$module" "  - $module" $true
    }
    
    # Check for native modules (sqlite3)
    if (Test-Path "backend/node_modules/sqlite3") {
        $sqliteBuild = Test-Path "backend/node_modules/sqlite3/build"
        if ($sqliteBuild) {
            Write-Host "OK SQLite3 native module built" -ForegroundColor Green
        } else {
            Write-Host "WARN SQLite3 not built (may need rebuild)" -ForegroundColor Yellow
            $WarningCount++
        }
    }
} else {
    Write-Host "ERR Backend node_modules missing" -ForegroundColor Red
    $ErrorCount++
}
Write-Host ""

# Calculate sizes
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Package Size Analysis" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

function Get-DirectorySize {
    param($Path)
    if (Test-Path $Path) {
        $size = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        return [math]::Round($size / 1MB, 2)
    }
    return 0
}

$backendSize = Get-DirectorySize "backend"
$buildSize = Get-DirectorySize "build"
$nodeModulesSize = Get-DirectorySize "node_modules"
$backendNodeModulesSize = Get-DirectorySize "backend/node_modules"

Write-Host "Backend folder: $backendSize MB" -ForegroundColor Cyan
Write-Host "Build folder: $buildSize MB" -ForegroundColor Cyan
Write-Host "Root node_modules: $nodeModulesSize MB" -ForegroundColor Cyan
Write-Host "Backend node_modules: $backendNodeModulesSize MB" -ForegroundColor Cyan
Write-Host "Total package size (est): $([math]::Round($backendSize + $buildSize, 2)) MB" -ForegroundColor Cyan
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Verification Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($ErrorCount -eq 0 -and $WarningCount -eq 0) {
    Write-Host "OK All checks passed!" -ForegroundColor Green
    Write-Host "  The package is ready for standalone deployment." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Run: npm run build:installer" -ForegroundColor White
    Write-Host "  2. Test the installer on a clean machine" -ForegroundColor White
    Write-Host "  3. Ensure Node.js is installed on target machines" -ForegroundColor White
} elseif ($ErrorCount -eq 0) {
    Write-Host "WARN Passed with warnings ($WarningCount warnings)" -ForegroundColor Yellow
    Write-Host "  The package should work but may have minor issues." -ForegroundColor Yellow
    Write-Host "  Review warnings above and fix if necessary." -ForegroundColor Yellow
} else {
    Write-Host "ERR Verification failed ($ErrorCount errors, $WarningCount warnings)" -ForegroundColor Red
    Write-Host "  Please fix the errors above before building installer." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Common fixes:" -ForegroundColor Yellow
    Write-Host "  - Run: npm install" -ForegroundColor White
    Write-Host "  - Run: cd backend && npm install" -ForegroundColor White
    Write-Host "  - Run: npm run build" -ForegroundColor White
    Write-Host "  - Run: powershell -File ./prepare-backend.ps1" -ForegroundColor White
    exit 1
}

Write-Host ""
