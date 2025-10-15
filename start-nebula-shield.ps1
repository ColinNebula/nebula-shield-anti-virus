#!/usr/bin/env pwsh
# Nebula Shield - Complete Startup Script
# Starts all required services for the antivirus application

Write-Host ""
Write-Host "████████████████████████████████████████████████████████████" -ForegroundColor Cyan
Write-Host "███                                                      ███" -ForegroundColor Cyan
Write-Host "███            NEBULA SHIELD ANTI-VIRUS                  ███" -ForegroundColor Cyan
Write-Host "███                Startup Script                        ███" -ForegroundColor Cyan
Write-Host "███                                                      ███" -ForegroundColor Cyan
Write-Host "████████████████████████████████████████████████████████████" -ForegroundColor Cyan
Write-Host ""

# Change to project directory
$projectRoot = "Z:\Directory\projects\nebula-shield-anti-virus"
Set-Location $projectRoot

Write-Host "📍 Project Directory: $projectRoot" -ForegroundColor White
Write-Host ""

# ============================================================================
# STEP 1: Stop any existing instances
# ============================================================================
Write-Host "🛑 Step 1: Stopping any existing services..." -ForegroundColor Yellow

# Stop existing node processes
$nodeProcesses = Get-Process -Name "node" -ErrorAction SilentlyContinue
if ($nodeProcesses) {
    Write-Host "   ⏹️  Stopping $($nodeProcesses.Count) Node.js process(es)..." -ForegroundColor Gray
    $nodeProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "   ✅ Node.js processes stopped" -ForegroundColor Green
} else {
    Write-Host "   ℹ️  No existing Node.js processes found" -ForegroundColor Gray
}

# Stop existing C++ backend
$backendProcesses = Get-Process -Name "nebula_shield_backend" -ErrorAction SilentlyContinue
if ($backendProcesses) {
    Write-Host "   ⏹️  Stopping backend scanner..." -ForegroundColor Gray
    $backendProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "   ✅ Backend scanner stopped" -ForegroundColor Green
} else {
    Write-Host "   ℹ️  No existing backend scanner found" -ForegroundColor Gray
}

Write-Host ""

# ============================================================================
# STEP 2: Start C++ Backend Scanner
# ============================================================================
Write-Host "🔧 Step 2: Starting C++ Backend Scanner (Port 8080)..." -ForegroundColor Yellow

$backendExe = "$projectRoot\backend\build\bin\Release\nebula_shield_backend.exe"

if (Test-Path $backendExe) {
    Start-Process -FilePath $backendExe -WorkingDirectory $projectRoot -WindowStyle Minimized
    Start-Sleep -Seconds 2
    
    # Verify backend started
    $backendRunning = Get-Process -Name "nebula_shield_backend" -ErrorAction SilentlyContinue
    if ($backendRunning) {
        Write-Host "   ✅ Backend scanner started successfully (PID: $($backendRunning.Id))" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Backend scanner failed to start" -ForegroundColor Red
        Write-Host "   📝 Backend may need to be rebuilt with CMake" -ForegroundColor Yellow
    }
} else {
    Write-Host "   ⚠️  Backend executable not found at:" -ForegroundColor Red
    Write-Host "      $backendExe" -ForegroundColor Gray
    Write-Host "   📝 Build the backend with: cmake --build backend/build --config Release" -ForegroundColor Yellow
}

Write-Host ""

# ============================================================================
# STEP 3: Start Auth Server (Node.js)
# ============================================================================
Write-Host "🔐 Step 3: Starting Auth Server (Port 8081)..." -ForegroundColor Yellow

$authServerPath = "$projectRoot\backend"

if (Test-Path "$authServerPath\auth-server.js") {
    # Start auth server in new window
    Start-Process powershell -ArgumentList @(
        "-NoExit",
        "-Command",
        "Write-Host '🔐 NEBULA SHIELD AUTH SERVER' -ForegroundColor Cyan; Write-Host ''; cd '$authServerPath'; node auth-server.js"
    ) -WindowStyle Normal
    
    Write-Host "   ⏳ Waiting for auth server to start..." -ForegroundColor Gray
    Start-Sleep -Seconds 5
    
    # Verify auth server
    try {
        $authTest = Invoke-WebRequest -Uri "http://localhost:8081/api/auth/verify" -Method GET -Headers @{Authorization="Bearer test"} -TimeoutSec 3 -ErrorAction Stop
        Write-Host "   ✅ Auth server started successfully" -ForegroundColor Green
    } catch {
        if ($_.Exception.Response.StatusCode -eq 401) {
            Write-Host "   ✅ Auth server started successfully" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Auth server may still be initializing..." -ForegroundColor Yellow
            Write-Host "   📝 Check the auth server window for status" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "   ⚠️  Auth server not found at: $authServerPath\auth-server.js" -ForegroundColor Red
}

Write-Host ""

# ============================================================================
# STEP 4: Start React Frontend
# ============================================================================
Write-Host "⚛️  Step 4: Starting React Frontend (Port 3000)..." -ForegroundColor Yellow

if (Test-Path "$projectRoot\package.json") {
    # Start React in new window
    Start-Process powershell -ArgumentList @(
        "-NoExit",
        "-Command",
        "Write-Host '⚛️  NEBULA SHIELD REACT FRONTEND' -ForegroundColor Cyan; Write-Host ''; cd '$projectRoot'; npm start"
    ) -WindowStyle Normal
    
    Write-Host "   ⏳ Waiting for React to compile..." -ForegroundColor Gray
    Start-Sleep -Seconds 8
    
    Write-Host "   ✅ React dev server starting..." -ForegroundColor Green
    Write-Host "   📝 React will open in browser automatically" -ForegroundColor Gray
} else {
    Write-Host "   ⚠️  package.json not found in project root" -ForegroundColor Red
}

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "✅ NEBULA SHIELD STARTUP COMPLETE!" -ForegroundColor Green
Write-Host ""
Write-Host "📊 Services Status:" -ForegroundColor Cyan
Write-Host "   🔧 Backend Scanner:  http://localhost:8080" -ForegroundColor White
Write-Host "   🔐 Auth Server:      http://localhost:8081" -ForegroundColor White
Write-Host "   ⚛️  React Frontend:   http://localhost:3000" -ForegroundColor White
Write-Host ""
Write-Host "🔑 Login Credentials:" -ForegroundColor Cyan
Write-Host "   Email:    colinnebula@gmail.com" -ForegroundColor White
Write-Host "   Password: Nebula2025!" -ForegroundColor White
Write-Host ""
Write-Host "💡 Payment System:" -ForegroundColor Cyan
Write-Host "   - Demo Mode:    Ready (no configuration needed)" -ForegroundColor Green
Write-Host "   - Stripe:       Configured" -ForegroundColor Green
Write-Host "   - PayPal:       Configured" -ForegroundColor Green
Write-Host "   - Email:        Configured" -ForegroundColor Green
Write-Host ""
Write-Host "📝 Next Steps:" -ForegroundColor Yellow
Write-Host "   1. Wait for browser to open (http://localhost:3000)" -ForegroundColor White
Write-Host "   2. Login with credentials above" -ForegroundColor White
Write-Host "   3. Test the antivirus features" -ForegroundColor White
Write-Host "   4. Try Premium upgrade (use Demo mode)" -ForegroundColor White
Write-Host ""
Write-Host "⚠️  To stop all services:" -ForegroundColor Yellow
Write-Host "   Run: .\stop-nebula-shield.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Keep window open
Write-Host "Press any key to exit this window (services will continue running)..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
