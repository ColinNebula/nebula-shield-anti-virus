# Pre-Build Environment Check
# Verifies all prerequisites are met before building the installer

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Nebula Shield - Environment Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"
$AllGood = $true

# Check 1: Node.js
Write-Host "[1/5] Checking Node.js..." -ForegroundColor Yellow
try {
    $nodeVersion = & node --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ Node.js installed: $nodeVersion" -ForegroundColor Green
    } else {
        Write-Host "  ❌ Node.js not found!" -ForegroundColor Red
        Write-Host "     Download from: https://nodejs.org/" -ForegroundColor Yellow
        $AllGood = $false
    }
} catch {
    Write-Host "  ❌ Node.js not found!" -ForegroundColor Red
    Write-Host "     Download from: https://nodejs.org/" -ForegroundColor Yellow
    $AllGood = $false
}

# Check 2: NPM Dependencies
Write-Host "`n[2/5] Checking NPM dependencies..." -ForegroundColor Yellow
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (Test-Path (Join-Path $ProjectRoot "node_modules")) {
    Write-Host "  ✅ React dependencies installed" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  React dependencies not found" -ForegroundColor Yellow
    Write-Host "     Run: npm install" -ForegroundColor Cyan
    $AllGood = $false
}

if (Test-Path (Join-Path $ProjectRoot "backend\node_modules")) {
    Write-Host "  ✅ Auth server dependencies installed" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Auth server dependencies not found" -ForegroundColor Yellow
    Write-Host "     Run: cd backend && npm install" -ForegroundColor Cyan
    $AllGood = $false
}

# Check 3: C++ Backend
Write-Host "`n[3/5] Checking C++ backend..." -ForegroundColor Yellow
$BackendExe = Join-Path $ProjectRoot "backend\build\bin\Release\nebula_shield_backend.exe"
if (Test-Path $BackendExe) {
    $exeSize = [math]::Round((Get-Item $BackendExe).Length / 1MB, 2)
    Write-Host "  ✅ Backend executable found ($exeSize MB)" -ForegroundColor Green
} else {
    Write-Host "  ❌ Backend executable not found!" -ForegroundColor Red
    Write-Host "     Build with: cd backend\build && cmake --build . --config Release" -ForegroundColor Yellow
    $AllGood = $false
}

# Check 4: Inno Setup
Write-Host "`n[4/5] Checking Inno Setup..." -ForegroundColor Yellow
$InnoSetupPaths = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
)

$InnoFound = $false
foreach ($path in $InnoSetupPaths) {
    if (Test-Path $path) {
        Write-Host "  ✅ Inno Setup found: $path" -ForegroundColor Green
        $InnoFound = $true
        break
    }
}

if (!$InnoFound) {
    Write-Host "  ❌ Inno Setup not found!" -ForegroundColor Red
    Write-Host "     Download from: https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
    $AllGood = $false
}

# Check 5: Disk Space
Write-Host "`n[5/5] Checking disk space..." -ForegroundColor Yellow
$Drive = (Get-Item $ProjectRoot).PSDrive.Name
$FreeSpace = [math]::Round((Get-PSDrive $Drive).Free / 1GB, 2)
if ($FreeSpace -gt 1) {
    Write-Host "  ✅ Free space: $FreeSpace GB" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Low disk space: $FreeSpace GB" -ForegroundColor Yellow
    Write-Host "     Recommended: At least 1 GB free" -ForegroundColor Cyan
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
if ($AllGood) {
    Write-Host "  ✅ All checks passed!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "You're ready to build the installer!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Run: .\build-all.ps1" -ForegroundColor Cyan
} else {
    Write-Host "  ⚠️  Some requirements missing" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Please install missing components before building." -ForegroundColor Yellow
}
Write-Host ""
