# Quick Installer Build Script
# Optimized for fast development and testing

param(
    [string]$BuildType = "installer",  # installer, portable, both
    [switch]$SkipNpmInstall,
    [switch]$SkipBuild,
    [switch]$OpenOutput
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "        NEBULA SHIELD - QUICK INSTALLER BUILD" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Build Type: $BuildType" -ForegroundColor Yellow
Write-Host ""

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

try {
    # Step 1: Clean (Quick)
    Write-Host "[1/6] Quick cleanup..." -ForegroundColor Yellow
    if (Test-Path "dist") {
        Remove-Item "dist" -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path "installer/output") {
        Remove-Item "installer/output" -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path "installer/output" -Force | Out-Null
    Write-Host "  ✓ Cleaned in $($stopwatch.Elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Green

    # Step 2: Dependencies (Conditional)
    if (-not $SkipNpmInstall) {
        Write-Host ""
        Write-Host "[2/6] Installing dependencies..." -ForegroundColor Yellow
        $depStart = $stopwatch.Elapsed
        npm ci --silent
        if ($LASTEXITCODE -ne 0) { throw "NPM install failed" }
        
        # Backend dependencies
        Push-Location backend
        if (Test-Path "package.json") {
            npm ci --only=production --silent
            if ($LASTEXITCODE -ne 0) { 
                Pop-Location
                throw "Backend NPM install failed" 
            }
        }
        Pop-Location
        
        $depTime = ($stopwatch.Elapsed - $depStart).TotalSeconds
        Write-Host "  ✓ Dependencies ready in $($depTime.ToString('F1'))s" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "[2/6] Skipping dependency installation..." -ForegroundColor Gray
    }

    # Step 3: Build (Conditional)
    if (-not $SkipBuild) {
        Write-Host ""
        Write-Host "[3/6] Building application..." -ForegroundColor Yellow
        $buildStart = $stopwatch.Elapsed
        
        $env:NODE_ENV = "production"
        npm run build --silent
        if ($LASTEXITCODE -ne 0) { throw "Build failed" }
        
        $buildTime = ($stopwatch.Elapsed - $buildStart).TotalSeconds
        Write-Host "  ✓ Built in $($buildTime.ToString('F1'))s" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "[3/6] Skipping build (using existing)..." -ForegroundColor Gray
        if (-not (Test-Path "build")) {
            throw "No build directory found. Remove -SkipBuild flag."
        }
    }

    # Step 4: Prepare Backend
    Write-Host ""
    Write-Host "[4/6] Preparing backend..." -ForegroundColor Yellow
    $backendStart = $stopwatch.Elapsed
    
    # Quick backend setup
    Push-Location backend
    if (-not (Test-Path "data")) {
        New-Item -ItemType Directory -Path "data" -Force | Out-Null
    }
    Pop-Location
    
    $backendTime = ($stopwatch.Elapsed - $backendStart).TotalSeconds
    Write-Host "  ✓ Backend ready in $($backendTime.ToString('F1'))s" -ForegroundColor Green

    # Step 5: Create Packages
    Write-Host ""
    Write-Host "[5/6] Creating packages..." -ForegroundColor Yellow
    $packageStart = $stopwatch.Elapsed

    # Use the standalone electron-builder config
    Copy-Item "electron-builder.standalone.json" "electron-builder.json" -Force

    if ($BuildType -eq "installer" -or $BuildType -eq "both") {
        Write-Host "  Creating installer package..." -ForegroundColor Gray
        npm run electron:build:win --silent
        if ($LASTEXITCODE -ne 0) { throw "Installer creation failed" }
    }

    if ($BuildType -eq "portable" -or $BuildType -eq "both") {
        Write-Host "  Creating portable package..." -ForegroundColor Gray
        # Copy the win-unpacked to create portable
        if (Test-Path "dist/win-unpacked") {
            $portableDir = "installer/output/Nebula-Shield-Portable-v1.0.0"
            Copy-Item -Path "dist/win-unpacked" -Destination $portableDir -Recurse -Force
            
            # Create launcher
            $launcher = @"
@echo off
title Nebula Shield Anti-Virus - Portable
echo Starting Nebula Shield Anti-Virus (Portable Edition)...
start "" "%~dp0\Nebula Shield Anti-Virus.exe"
"@
            $launcher | Out-File "$portableDir/Launch.bat" -Encoding ASCII
            
            # Create zip
            Compress-Archive -Path $portableDir -DestinationPath "$portableDir.zip" -Force
            Remove-Item $portableDir -Recurse -Force
        }
    }

    $packageTime = ($stopwatch.Elapsed - $packageStart).TotalSeconds
    Write-Host "  ✓ Packages created in $($packageTime.ToString('F1'))s" -ForegroundColor Green

    # Step 6: Summary
    Write-Host ""
    Write-Host "[6/6] Build summary..." -ForegroundColor Yellow
    
    $outputFiles = @()
    if (Test-Path "dist") {
        $outputFiles += Get-ChildItem -Path "dist" -Filter "*.exe" -Recurse
    }
    if (Test-Path "installer/output") {
        $outputFiles += Get-ChildItem -Path "installer/output" -File
    }

    if ($outputFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "CREATED FILES:" -ForegroundColor Green
        foreach ($file in $outputFiles) {
            $sizeInMB = [math]::Round($file.Length / 1MB, 2)
            Write-Host "  ✓ $($file.Name) - $sizeInMB MB" -ForegroundColor White
            Write-Host "    Location: $($file.FullName)" -ForegroundColor Gray
        }
    }

    $totalTime = $stopwatch.Elapsed.TotalSeconds
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host "BUILD COMPLETED SUCCESSFULLY IN $($totalTime.ToString('F1')) SECONDS!" -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Green
    
    if ($OpenOutput) {
        if (Test-Path "installer/output") {
            Invoke-Item "installer/output"
        } elseif (Test-Path "dist") {
            Invoke-Item "dist"
        }
    }

} catch {
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Red
    Write-Host "BUILD FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "=================================================================" -ForegroundColor Red
    Write-Host "Time elapsed: $($stopwatch.Elapsed.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Yellow
    exit 1
} finally {
    $stopwatch.Stop()
}

Write-Host ""
Write-Host "USAGE EXAMPLES:" -ForegroundColor Cyan
Write-Host "  .\build-quick-installer.ps1                    # Full build (installer)"
Write-Host "  .\build-quick-installer.ps1 -BuildType both    # Both installer and portable"
Write-Host "  .\build-quick-installer.ps1 -SkipBuild         # Use existing build"
Write-Host "  .\build-quick-installer.ps1 -SkipNpmInstall    # Skip dependency install"
Write-Host "  .\build-quick-installer.ps1 -OpenOutput        # Open output folder when done"
Write-Host ""