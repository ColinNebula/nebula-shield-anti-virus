# Restart Auth Service to Apply Forgot Password Feature
Write-Host "`n════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   RESTARTING AUTH SERVICE" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan

# Stop auth service
Write-Host "`n1. Stopping Auth Service..." -ForegroundColor Yellow
& "C:\Program Files\Nebula Shield\nssm.exe" stop NebulaShieldAuth
Start-Sleep -Seconds 2

# Start auth service
Write-Host "2. Starting Auth Service..." -ForegroundColor Yellow
& "C:\Program Files\Nebula Shield\nssm.exe" start NebulaShieldAuth
Start-Sleep -Seconds 3

# Verify
Write-Host "`n3. Verifying services..." -ForegroundColor Yellow
$authStatus = & "C:\Program Files\Nebula Shield\nssm.exe" status NebulaShieldAuth

if ($authStatus -eq "SERVICE_RUNNING") {
    Write-Host "   ✅ Auth Service: RUNNING" -ForegroundColor Green
} else {
    Write-Host "   ❌ Auth Service: $authStatus" -ForegroundColor Red
}

# Test endpoints
Write-Host "`n4. Testing endpoints..." -ForegroundColor Yellow

# Test login
Write-Host "   Testing login endpoint..." -ForegroundColor Gray
try {
    $loginBody = @{
        email = "colinnebula@nebula3ddev.com"
        password = "Nebula2025!"
    } | ConvertTo-Json
    
    $loginResponse = Invoke-RestMethod -Uri "http://localhost:8081/api/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
    Write-Host "   ✅ Login endpoint: WORKING" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Login endpoint: FAILED" -ForegroundColor Red
}

# Test forgot password
Write-Host "   Testing forgot-password endpoint..." -ForegroundColor Gray
try {
    $forgotBody = @{
        email = "colinnebula@nebula3ddev.com"
    } | ConvertTo-Json
    
    $forgotResponse = Invoke-RestMethod -Uri "http://localhost:8081/api/auth/forgot-password" -Method POST -Body $forgotBody -ContentType "application/json"
    Write-Host "   ✅ Forgot Password endpoint: WORKING" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Forgot Password endpoint: NOT FOUND" -ForegroundColor Red
    Write-Host "   Response: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "`n════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   RESTART COMPLETE" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`n📧 Your credentials:" -ForegroundColor Cyan
Write-Host "   Email: colinnebula@nebula3ddev.com" -ForegroundColor White
Write-Host "   Password: Nebula2025!" -ForegroundColor White
Write-Host "`n🌐 Access: http://localhost:3000/login" -ForegroundColor Yellow

Write-Host "`nPress any key to close..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
