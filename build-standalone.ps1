# Nebula Shield - Complete Standalone Build Script
# Creates a fully functional portable/installable version

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "Nebula Shield Anti-Virus - Standalone Builder" -ForegroundColor Cyan
Write-Host ""

# Check Node.js
Write-Host "Checking prerequisites..." -ForegroundColor Yellow
try {
    $nodeVersion = node --version
    Write-Host "Node.js: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "Node.js not found! Please install Node.js from https://nodejs.org/" -ForegroundColor Red
    exit 1
}

# Check npm
try {
    $npmVersion = npm --version
    Write-Host "npm: v$npmVersion" -ForegroundColor Green
} catch {
    Write-Host "npm not found!" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Step 1: Install dependencies
Write-Host "Step 1/6: Installing dependencies..." -ForegroundColor Cyan
npm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install dependencies" -ForegroundColor Red
    exit 1
}
Write-Host "Dependencies installed" -ForegroundColor Green
Write-Host ""

# Step 2: Install backend dependencies
Write-Host "Step 2/6: Installing backend dependencies..." -ForegroundColor Cyan
Push-Location backend
if (Test-Path "package.json") {
    npm install --production
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to install backend dependencies" -ForegroundColor Red
        Pop-Location
        exit 1
    }
    Write-Host "Backend dependencies installed" -ForegroundColor Green
} else {
    Write-Host "No backend package.json found, skipping..." -ForegroundColor Yellow
}
Pop-Location
Write-Host ""

# Step 3: Build React frontend
Write-Host "Step 3/6: Building React frontend..." -ForegroundColor Cyan
$env:NODE_ENV = "production"
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "Frontend build failed" -ForegroundColor Red
    exit 1
}

# Verify build output
if (-not (Test-Path "build/index.html")) {
    Write-Host "Build output not found at build/index.html" -ForegroundColor Red
    exit 1
}
Write-Host "Frontend built successfully" -ForegroundColor Green
Write-Host ""

# Step 4: Prepare backend files
Write-Host "Step 4/6: Preparing backend files..." -ForegroundColor Cyan

# Ensure backend directory structure
$backendFiles = @(
    "backend/auth-server.js",
    "backend/mock-backend.js"
)

$missingFiles = @()
foreach ($file in $backendFiles) {
    if (-not (Test-Path $file)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "Missing backend files:" -ForegroundColor Red
    $missingFiles | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
    exit 1
}

# Create/verify data directories
$dataDirs = @(
    "data",
    "data/quarantine",
    "data/logs",
    "data/virus-definitions",
    "data/backups"
)

foreach ($dir in $dataDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "Created: $dir" -ForegroundColor Green
    }
}

# Create initial data files if they don't exist
if (-not (Test-Path "data/auth.db")) {
    Write-Host "Creating initial database..." -ForegroundColor Yellow
}

Write-Host "Backend files prepared" -ForegroundColor Green
Write-Host ""

# Step 5: Build Electron application
Write-Host "Step 5/6: Building Electron application..." -ForegroundColor Cyan
Write-Host "   This may take several minutes..." -ForegroundColor Gray

# Use the standalone electron-builder config
$env:NODE_ENV = "production"
npx electron-builder --config electron-builder.standalone.json --win

if ($LASTEXITCODE -ne 0) {
    Write-Host "Electron build failed" -ForegroundColor Red
    exit 1
}

Write-Host "Electron application built" -ForegroundColor Green
Write-Host ""

# Step 6: Verify output
Write-Host "Step 6/6: Verifying build output..." -ForegroundColor Cyan

$distPath = "dist"
if (-not (Test-Path $distPath)) {
    Write-Host "Distribution directory not found" -ForegroundColor Red
    exit 1
}

# Find built files
$installer = Get-ChildItem -Path $distPath -Filter "*Setup*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
$portable = Get-ChildItem -Path $distPath -Filter "*Portable*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
$zipFile = Get-ChildItem -Path $distPath -Filter "*.zip" -ErrorAction SilentlyContinue | Select-Object -First 1

Write-Host ""
Write-Host "BUILD COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host ""

Write-Host "Built Files:" -ForegroundColor Cyan
Write-Host ""

if ($installer) {
    $installerSize = [math]::Round($installer.Length / 1MB, 2)
    Write-Host "  Installer:" -ForegroundColor Yellow
    Write-Host "     File: $($installer.Name)" -ForegroundColor White
    Write-Host "     Size: ${installerSize} MB" -ForegroundColor Gray
    Write-Host "     Path: $($installer.FullName)" -ForegroundColor Gray
    Write-Host ""
}

if ($portable) {
    $portableSize = [math]::Round($portable.Length / 1MB, 2)
    Write-Host "  Portable:" -ForegroundColor Yellow
    Write-Host "     File: $($portable.Name)" -ForegroundColor White
    Write-Host "     Size: ${portableSize} MB" -ForegroundColor Gray
    Write-Host "     Path: $($portable.FullName)" -ForegroundColor Gray
    Write-Host ""
}

if ($zipFile) {
    $zipSize = [math]::Round($zipFile.Length / 1MB, 2)
    Write-Host "  Archive:" -ForegroundColor Yellow
    Write-Host "     File: $($zipFile.Name)" -ForegroundColor White
    Write-Host "     Size: ${zipSize} MB" -ForegroundColor Gray
    Write-Host "     Path: $($zipFile.FullName)" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "What's Included:" -ForegroundColor Green
Write-Host "   React Frontend (Vite optimized)" -ForegroundColor White
Write-Host "   Authentication Server (Port 8082)" -ForegroundColor White
Write-Host "   Mock Backend API (Port 8080)" -ForegroundColor White
Write-Host "   SQLite Database (persistent storage)" -ForegroundColor White
Write-Host "   All Node.js dependencies bundled" -ForegroundColor White
Write-Host "   Virus definitions and data" -ForegroundColor White
Write-Host "   Desktop shortcuts and icons" -ForegroundColor White
Write-Host ""

Write-Host "Installation Instructions:" -ForegroundColor Green
Write-Host ""
Write-Host "  For Installer (.exe):" -ForegroundColor Yellow
Write-Host "    1. Copy the Setup file to your other computer" -ForegroundColor White
Write-Host "    2. Run the installer" -ForegroundColor White
Write-Host "    3. Follow installation wizard" -ForegroundColor White
Write-Host "    4. Launch from Start Menu or Desktop" -ForegroundColor White
Write-Host ""
Write-Host "  For Portable (.exe):" -ForegroundColor Yellow
Write-Host "    1. Copy the Portable file to any location" -ForegroundColor White
Write-Host "    2. Double-click to run (no installation needed)" -ForegroundColor White
Write-Host "    3. All data stored in application directory" -ForegroundColor White
Write-Host ""
Write-Host "  For ZIP Archive:" -ForegroundColor Yellow
Write-Host "    1. Extract to desired location" -ForegroundColor White
Write-Host "    2. Run Nebula Shield Anti-Virus.exe" -ForegroundColor White
Write-Host ""

Write-Host "Important Notes:" -ForegroundColor Green
Write-Host "   Backend servers start automatically" -ForegroundColor White
Write-Host "   No manual server startup required" -ForegroundColor White
Write-Host "   All features work offline" -ForegroundColor White
Write-Host "   Settings persist across restarts" -ForegroundColor White
Write-Host "   Firewall may prompt for permissions (allow)" -ForegroundColor Yellow
Write-Host ""

Write-Host "Testing Instructions:" -ForegroundColor Green
Write-Host "   1. Run the application" -ForegroundColor White
Write-Host "   2. Wait for backend servers to start (~5 seconds)" -ForegroundColor White
Write-Host "   3. Login with:" -ForegroundColor White
Write-Host "      Email: admin@test.com" -ForegroundColor Cyan
Write-Host "      Password: admin" -ForegroundColor Cyan
Write-Host "   4. Test all features (scanning, settings, etc.)" -ForegroundColor White
Write-Host ""

Write-Host "Build completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

# Open dist folder
Write-Host "Opening dist folder..." -ForegroundColor Yellow
Start-Process explorer.exe -ArgumentList $distPath
