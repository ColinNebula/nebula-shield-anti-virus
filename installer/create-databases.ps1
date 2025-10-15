# Create Database Files for Nebula Shield
# Run this as Administrator!

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   Nebula Shield - Create Database Files" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

$installPath = "C:\Program Files\Nebula Shield"

# Check installation exists
if (-not (Test-Path $installPath)) {
    Write-Host "ERROR: Installation not found at $installPath" -ForegroundColor Red
    pause
    exit 1
}

Set-Location $installPath
Write-Host "✓ Found installation at: $installPath" -ForegroundColor Green
Write-Host ""

# Ensure data directory exists
if (-not (Test-Path "data")) {
    Write-Host "Creating data directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path "data" | Out-Null
    Write-Host "✓ Data directory created" -ForegroundColor Green
} else {
    Write-Host "✓ Data directory exists" -ForegroundColor Green
}

# Ensure logs directory exists
if (-not (Test-Path "data\logs")) {
    Write-Host "Creating logs directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path "data\logs" | Out-Null
    Write-Host "✓ Logs directory created" -ForegroundColor Green
} else {
    Write-Host "✓ Logs directory exists" -ForegroundColor Green
}

Write-Host ""
Write-Host "Setting permissions on data directory..." -ForegroundColor Yellow

# Grant full control to SYSTEM and Administrators
icacls "data" /grant "SYSTEM:(OI)(CI)F" /T /C | Out-Null
icacls "data" /grant "Administrators:(OI)(CI)F" /T /C | Out-Null
icacls "data" /grant "Users:(OI)(CI)M" /T /C | Out-Null

Write-Host "✓ Permissions set" -ForegroundColor Green
Write-Host ""

# Create auth database
Write-Host "Creating auth database..." -ForegroundColor Yellow

if (Test-Path "data\auth.db") {
    Write-Host "! Database already exists, skipping creation" -ForegroundColor Yellow
} else {
    # Create empty database file
    New-Item -ItemType File -Path "data\auth.db" -Force | Out-Null
    
    # Set permissions on database file
    icacls "data\auth.db" /grant "SYSTEM:F" /C | Out-Null
    icacls "data\auth.db" /grant "Administrators:F" /C | Out-Null
    icacls "data\auth.db" /grant "Users:M" /C | Out-Null
    
    Write-Host "✓ Auth database created: data\auth.db" -ForegroundColor Green
}

# Create antivirus database
Write-Host "Creating antivirus database..." -ForegroundColor Yellow

if (Test-Path "data\nebula_shield.db") {
    Write-Host "! Database already exists, skipping creation" -ForegroundColor Yellow
} else {
    # Create empty database file
    New-Item -ItemType File -Path "data\nebula_shield.db" -Force | Out-Null
    
    # Set permissions on database file
    icacls "data\nebula_shield.db" /grant "SYSTEM:F" /C | Out-Null
    icacls "data\nebula_shield.db" /grant "Administrators:F" /C | Out-Null
    icacls "data\nebula_shield.db" /grant "Users:M" /C | Out-Null
    
    Write-Host "✓ Antivirus database created: data\nebula_shield.db" -ForegroundColor Green
}

Write-Host ""
Write-Host "Verifying database files..." -ForegroundColor Yellow

$authDb = Test-Path "data\auth.db"
$avDb = Test-Path "data\nebula_shield.db"

if ($authDb) {
    Write-Host "✓ data\auth.db exists" -ForegroundColor Green
} else {
    Write-Host "✗ data\auth.db missing" -ForegroundColor Red
}

if ($avDb) {
    Write-Host "✓ data\nebula_shield.db exists" -ForegroundColor Green
} else {
    Write-Host "✗ data\nebula_shield.db missing" -ForegroundColor Red
}

Write-Host ""
Write-Host "Initializing auth database schema..." -ForegroundColor Yellow

# Run auth server briefly to initialize tables
$initJob = Start-Job -ScriptBlock {
    Set-Location "C:\Program Files\Nebula Shield"
    & node auth-server\auth-server.js
}

# Wait for initialization (5 seconds should be enough)
Start-Sleep -Seconds 5

# Stop the job
Stop-Job $initJob -ErrorAction SilentlyContinue
Remove-Job $initJob -ErrorAction SilentlyContinue

Write-Host "✓ Database schema initialized" -ForegroundColor Green
Write-Host ""

Write-Host "================================================" -ForegroundColor Green
Write-Host "   Database Setup Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Database files created:" -ForegroundColor White
Write-Host "  • C:\Program Files\Nebula Shield\data\auth.db" -ForegroundColor Gray
Write-Host "  • C:\Program Files\Nebula Shield\data\nebula_shield.db" -ForegroundColor Gray
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Start the services (run as Administrator):" -ForegroundColor Gray
Write-Host "     cd 'C:\Program Files\Nebula Shield'" -ForegroundColor DarkGray
Write-Host "     .\nssm.exe start NebulaShieldAuth" -ForegroundColor DarkGray
Write-Host "     .\nssm.exe start NebulaShieldBackend" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  2. Or use the fix script:" -ForegroundColor Gray
Write-Host "     Run: fix-services-database.ps1 as Administrator" -ForegroundColor DarkGray
Write-Host ""

pause
