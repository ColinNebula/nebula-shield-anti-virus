# Quick Fix: Add Frontend Service to Existing Installation
# Run this as Administrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Nebula Shield - Frontend Service Fix" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script requires administrator privileges!" -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

$InstallPath = "C:\Program Files\Nebula Shield"
$BuildPath = "Z:\Directory\projects\nebula-shield-anti-virus\installer\build"

# Check if Nebula Shield is installed
if (!(Test-Path $InstallPath)) {
    Write-Host "ERROR: Nebula Shield not found at $InstallPath" -ForegroundColor Red
    Write-Host "Please install Nebula Shield first." -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "Found Nebula Shield installation at: $InstallPath" -ForegroundColor Green
Write-Host ""

# Copy frontend-server folder
Write-Host "[1/3] Copying frontend server files..." -ForegroundColor Yellow
$FrontendServerDest = Join-Path $InstallPath "frontend-server"
if (Test-Path $FrontendServerDest) {
    Write-Host "  Removing old frontend-server folder..." -ForegroundColor Gray
    Remove-Item -Recurse -Force $FrontendServerDest
}
Copy-Item -Recurse -Path (Join-Path $BuildPath "frontend-server") -Destination $FrontendServerDest
Write-Host "  ✅ Frontend server files copied" -ForegroundColor Green
Write-Host ""

# Check if service already exists
Write-Host "[2/3] Checking for existing service..." -ForegroundColor Yellow
$ServiceExists = Get-Service -Name "NebulaShieldFrontend" -ErrorAction SilentlyContinue
if ($ServiceExists) {
    Write-Host "  Service already exists. Stopping and removing..." -ForegroundColor Gray
    & "$InstallPath\nssm.exe" stop NebulaShieldFrontend
    & "$InstallPath\nssm.exe" remove NebulaShieldFrontend confirm
    Start-Sleep -Seconds 2
}

# Install frontend service
Write-Host "[3/3] Installing frontend service..." -ForegroundColor Yellow
& "$InstallPath\nssm.exe" install NebulaShieldFrontend "C:\Program Files\nodejs\node.exe" "frontend-server\node_modules\serve\build\main.js" "-s frontend -l 3000"
& "$InstallPath\nssm.exe" set NebulaShieldFrontend AppDirectory "$InstallPath"
& "$InstallPath\nssm.exe" set NebulaShieldFrontend DisplayName "Nebula Shield Frontend Server"
& "$InstallPath\nssm.exe" set NebulaShieldFrontend Description "Web interface server"
& "$InstallPath\nssm.exe" set NebulaShieldFrontend Start SERVICE_AUTO_START
& "$InstallPath\nssm.exe" set NebulaShieldFrontend AppStdout "$InstallPath\data\logs\frontend-service.log"
& "$InstallPath\nssm.exe" set NebulaShieldFrontend AppStderr "$InstallPath\data\logs\frontend-error.log"
Write-Host "  ✅ Service installed" -ForegroundColor Green
Write-Host ""

# Start the service
Write-Host "Starting frontend service..." -ForegroundColor Yellow
& "$InstallPath\nssm.exe" start NebulaShieldFrontend
Start-Sleep -Seconds 3

# Verify all services are running
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$Services = @("NebulaShieldBackend", "NebulaShieldAuth", "NebulaShieldFrontend")
foreach ($ServiceName in $Services) {
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($Service) {
        $StatusColor = if ($Service.Status -eq "Running") { "Green" } else { "Red" }
        Write-Host "  $ServiceName : " -NoNewline
        Write-Host "$($Service.Status)" -ForegroundColor $StatusColor
    } else {
        Write-Host "  $ServiceName : " -NoNewline
        Write-Host "NOT FOUND" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "You can now access Nebula Shield at:" -ForegroundColor Cyan
Write-Host "  http://localhost:3000" -ForegroundColor White
Write-Host ""
Write-Host "Press any key to open in browser..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Start-Process "http://localhost:3000"
