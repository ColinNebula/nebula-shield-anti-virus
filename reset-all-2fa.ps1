# Reset All Users 2FA Script
# This script calls the admin API endpoint to reset all users 2FA settings

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Nebula Shield - Reset All 2FA" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$API_URL = "http://localhost:8082/api/admin/reset-2fa"

# You need to login as admin first and get a token
# For quick testing, using admin@test.com / admin credentials
$LOGIN_URL = "http://localhost:8082/api/auth/login"

Write-Host "Step 1: Logging in as admin..." -ForegroundColor Yellow

# Login to get token
$loginBody = @{
    email = "admin@test.com"
    password = "admin"
} | ConvertTo-Json

try {
    $loginResponse = Invoke-RestMethod -Uri $LOGIN_URL -Method POST -Body $loginBody -ContentType "application/json"
    
    if ($loginResponse.success) {
        Write-Host "Success: Login successful!" -ForegroundColor Green
        $token = $loginResponse.token
        
        Write-Host ""
        Write-Host "Step 2: Resetting all users 2FA..." -ForegroundColor Yellow
        
        # Call reset 2FA endpoint
        $headers = @{
            "Authorization" = "Bearer $token"
        }
        
        $resetResponse = Invoke-RestMethod -Uri $API_URL -Method POST -Headers $headers -ContentType "application/json"
        
        if ($resetResponse.success) {
            Write-Host "Success!" -ForegroundColor Green
            Write-Host ""
            Write-Host "Message: $($resetResponse.message)" -ForegroundColor Cyan
            Write-Host "Users affected: $($resetResponse.count)" -ForegroundColor Cyan
            Write-Host "Note: $($resetResponse.note)" -ForegroundColor Yellow
        } else {
            Write-Host "Failed: $($resetResponse.error)" -ForegroundColor Red
        }
    } else {
        Write-Host "Login failed: $($loginResponse.error)" -ForegroundColor Red
        Write-Host "Make sure the backend server is running on port 8082" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Make sure:" -ForegroundColor Yellow
    Write-Host "  1. Backend server is running (npm run backend)" -ForegroundColor Yellow
    Write-Host "  2. Server is accessible on http://localhost:8082" -ForegroundColor Yellow
    Write-Host "  3. Admin account exists (admin@test.com / admin)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
