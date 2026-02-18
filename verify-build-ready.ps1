# ═══════════════════════════════════════════════════════════
# Nebula Shield - Pre-Build Verification Script
# Checks if everything is ready for standalone build
# ═══════════════════════════════════════════════════════════

$ErrorActionPreference = "Continue"
$allChecksPass = $true

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Nebula Shield - Pre-Build Verification                ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check 1: Node.js
Write-Host "🔍 Checking Node.js..." -ForegroundColor Yellow
try {
    $nodeVersion = node --version
    Write-Host "   ✅ Node.js installed: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Node.js NOT FOUND!" -ForegroundColor Red
    Write-Host "      Download from: https://nodejs.org/" -ForegroundColor Yellow
    $allChecksPass = $false
}

# Check 2: npm
Write-Host "🔍 Checking npm..." -ForegroundColor Yellow
try {
    $npmVersion = npm --version
    Write-Host "   ✅ npm installed: v$npmVersion" -ForegroundColor Green
} catch {
    Write-Host "   ❌ npm NOT FOUND!" -ForegroundColor Red
    $allChecksPass = $false
}

# Check 3: Required files
Write-Host "🔍 Checking required files..." -ForegroundColor Yellow

$requiredFiles = @(
    "package.json",
    "vite.config.js",
    "public/electron.js",
    "public/preload.js",
    "backend/auth-server.js",
    "backend/mock-backend.js",
    "electron-builder.standalone.json"
)

foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Host "   ✅ $file" -ForegroundColor Green
    } else {
        Write-Host "   ❌ $file NOT FOUND!" -ForegroundColor Red
        $allChecksPass = $false
    }
}

# Check 4: node_modules
Write-Host "🔍 Checking dependencies..." -ForegroundColor Yellow
if (Test-Path "node_modules") {
    $packageCount = (Get-ChildItem "node_modules" -Directory).Count
    Write-Host "   ✅ node_modules exists ($packageCount packages)" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  node_modules NOT FOUND - will be installed during build" -ForegroundColor Yellow
}

# Check 5: Backend dependencies
Write-Host "🔍 Checking backend dependencies..." -ForegroundColor Yellow
if (Test-Path "backend/node_modules") {
    $backendPackageCount = (Get-ChildItem "backend/node_modules" -Directory).Count
    Write-Host "   ✅ backend/node_modules exists ($backendPackageCount packages)" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  backend/node_modules NOT FOUND - will be installed during build" -ForegroundColor Yellow
}

# Check 6: Disk space
Write-Host "🔍 Checking disk space..." -ForegroundColor Yellow
$drive = (Get-Location).Drive
$freeSpace = [math]::Round((Get-PSDrive $drive.Name).Free / 1GB, 2)
if ($freeSpace -gt 2) {
    Write-Host "   ✅ Free space: ${freeSpace} GB (sufficient)" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Free space: ${freeSpace} GB (low - need at least 2 GB)" -ForegroundColor Yellow
    $allChecksPass = $false
}

# Check 7: Build resources
Write-Host "🔍 Checking build resources..." -ForegroundColor Yellow
if (Test-Path "build-resources/icon.ico") {
    Write-Host "   ✅ icon.ico exists" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  icon.ico missing - using default" -ForegroundColor Yellow
}

# Check 8: Electron
Write-Host "🔍 Checking Electron..." -ForegroundColor Yellow
if (Test-Path "node_modules/.bin/electron.cmd") {
    Write-Host "   ✅ Electron binary found" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Electron NOT FOUND - will be installed" -ForegroundColor Yellow
}

# Check 9: electron-builder
Write-Host "🔍 Checking electron-builder..." -ForegroundColor Yellow
if (Test-Path "node_modules/electron-builder") {
    Write-Host "   ✅ electron-builder installed" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  electron-builder NOT FOUND - will be installed" -ForegroundColor Yellow
}

# Check 10: Source files
Write-Host "🔍 Checking source files..." -ForegroundColor Yellow
$srcCount = (Get-ChildItem "src" -Recurse -File).Count
if ($srcCount -gt 0) {
    Write-Host "   ✅ Source files: $srcCount files" -ForegroundColor Green
} else {
    Write-Host "   ❌ No source files found!" -ForegroundColor Red
    $allChecksPass = $false
}

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

if ($allChecksPass) {
    Write-Host "✅ All critical checks passed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "You're ready to build! Run:" -ForegroundColor White
    Write-Host "   .\BUILD-STANDALONE.bat" -ForegroundColor Cyan
    Write-Host "   or" -ForegroundColor Gray
    Write-Host "   npm run build:standalone" -ForegroundColor Cyan
} else {
    Write-Host "❌ Some checks failed!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please fix the issues above before building." -ForegroundColor Yellow
}

Write-Host ""

# Estimated build time
Write-Host "📊 Estimated Build Information:" -ForegroundColor Cyan
Write-Host "   • Duration: 5-10 minutes (first build)" -ForegroundColor White
Write-Host "   • Duration: 2-5 minutes (subsequent builds)" -ForegroundColor White
Write-Host "   • Output size: ~150-200 MB" -ForegroundColor White
Write-Host "   • Formats: Installer + Portable + ZIP" -ForegroundColor White
Write-Host ""

exit $(if ($allChecksPass) { 0 } else { 1 })
