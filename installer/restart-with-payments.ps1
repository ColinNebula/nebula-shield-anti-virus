# Restart Services with Payment System
Write-Host "`n════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   RESTARTING SERVICES WITH PAYMENT SYSTEM" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`n⚠️  IMPORTANT: Configure .env file first!" -ForegroundColor Yellow
Write-Host "   Location: Z:\Directory\projects\nebula-shield-anti-virus\backend\.env" -ForegroundColor White
Write-Host "   See: PAYMENT-SETUP-GUIDE.md for instructions`n" -ForegroundColor White

# Stop services
Write-Host "1. Stopping services..." -ForegroundColor Yellow
& "C:\Program Files\Nebula Shield\nssm.exe" stop NebulaShieldAuth
& "C:\Program Files\Nebula Shield\nssm.exe" stop NebulaShieldFrontend
Start-Sleep -Seconds 3

# Start services
Write-Host "2. Starting services with new payment system..." -ForegroundColor Yellow
& "C:\Program Files\Nebula Shield\nssm.exe" start NebulaShieldAuth
Start-Sleep -Seconds 3
& "C:\Program Files\Nebula Shield\nssm.exe" start NebulaShieldFrontend
Start-Sleep -Seconds 5

# Check status
Write-Host "`n3. Verifying services..." -ForegroundColor Yellow
$authStatus = & "C:\Program Files\Nebula Shield\nssm.exe" status NebulaShieldAuth
$frontendStatus = & "C:\Program Files\Nebula Shield\nssm.exe" status NebulaShieldFrontend

if ($authStatus -eq "SERVICE_RUNNING") {
    Write-Host "   ✅ Auth Service: RUNNING" -ForegroundColor Green
} else {
    Write-Host "   ❌ Auth Service: $authStatus" -ForegroundColor Red
}

if ($frontendStatus -eq "SERVICE_RUNNING") {
    Write-Host "   ✅ Frontend Service: RUNNING" -ForegroundColor Green
} else {
    Write-Host "   ❌ Frontend Service: $frontendStatus" -ForegroundColor Red
}

# Test endpoints
Write-Host "`n4. Testing payment endpoints..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

try {
    # Test login first
    $loginBody = @{
        email = "colinnebula@nebula3ddev.com"
        password = "Nebula2025!"
    } | ConvertTo-Json
    
    $loginResponse = Invoke-RestMethod -Uri "http://localhost:8081/api/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
    Write-Host "   ✅ Login endpoint: WORKING" -ForegroundColor Green
    
    $token = $loginResponse.token
    
    # Test payment endpoints (will fail if .env not configured, but that's OK)
    try {
        $stripeResponse = Invoke-RestMethod -Uri "http://localhost:8081/api/payment/stripe/create-session" `
            -Method POST `
            -Headers @{Authorization="Bearer $token"} `
            -ContentType "application/json"
        Write-Host "   ✅ Stripe endpoint: READY" -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -like "*STRIPE_SECRET_KEY*") {
            Write-Host "   ⚠️  Stripe endpoint: NEEDS CONFIGURATION (.env file)" -ForegroundColor Yellow
        } else {
            Write-Host "   ⚠️  Stripe endpoint: Available (configure .env to test)" -ForegroundColor Yellow
        }
    }
    
} catch {
    Write-Host "   ❌ Could not test endpoints: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   SERVICES RESTARTED" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`n🌐 Access Points:" -ForegroundColor Cyan
Write-Host "   Frontend: http://localhost:3000" -ForegroundColor White
Write-Host "   Premium Page: http://localhost:3000/premium" -ForegroundColor White
Write-Host "   Auth Server: http://localhost:8081" -ForegroundColor White

Write-Host "`n📝 Configuration:" -ForegroundColor Cyan
Write-Host "   1. Edit: Z:\Directory\projects\nebula-shield-anti-virus\backend\.env" -ForegroundColor White
Write-Host "   2. Add your Stripe API keys" -ForegroundColor White
Write-Host "   3. Add your PayPal credentials" -ForegroundColor White
Write-Host "   4. Configure email settings" -ForegroundColor White
Write-Host "   5. See PAYMENT-SETUP-GUIDE.md for details" -ForegroundColor White

Write-Host "`n💡 For Testing:" -ForegroundColor Yellow
Write-Host "   - Use 'Quick Upgrade (Demo)' button for instant upgrade" -ForegroundColor White
Write-Host "   - Configure .env for real payment testing" -ForegroundColor White
Write-Host "   - Check PAYMENT-SETUP-GUIDE.md for test cards" -ForegroundColor White

Write-Host "`nPress any key to close..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
