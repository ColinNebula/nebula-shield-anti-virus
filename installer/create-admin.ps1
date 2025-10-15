# Create Nebula Shield Administrator Account
# Run this script to create a super admin with full privileges

Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Nebula Shield - Create Administrator         ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Get admin credentials
Write-Host "Enter Administrator Details:" -ForegroundColor Yellow
Write-Host ""

$adminFullName = Read-Host "Full Name"
if ([string]::IsNullOrWhiteSpace($adminFullName)) {
    $adminFullName = "Nebula Shield Administrator"
}

$adminEmail = Read-Host "Email Address"
if ([string]::IsNullOrWhiteSpace($adminEmail)) {
    Write-Host "Error: Email is required!" -ForegroundColor Red
    pause
    exit 1
}

$adminPassword = Read-Host "Password" -AsSecureString
$adminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPassword)
)

if ($adminPasswordPlain.Length -lt 6) {
    Write-Host "Error: Password must be at least 6 characters!" -ForegroundColor Red
    pause
    exit 1
}

Write-Host ""
Write-Host "Creating administrator account..." -ForegroundColor Yellow

# Create the admin account via API
$body = @{
    fullName = $adminFullName
    email = $adminEmail
    password = $adminPasswordPlain
} | ConvertTo-Json

try {
    # Register the admin account
    $response = Invoke-RestMethod -Uri "http://localhost:8081/api/auth/register" `
        -Method POST `
        -Body $body `
        -ContentType "application/json" `
        -ErrorAction Stop
    
    if ($response.success) {
        Write-Host ""
        Write-Host "✓ Administrator account created successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Account Details:" -ForegroundColor Cyan
        Write-Host "  Name:  $adminFullName" -ForegroundColor White
        Write-Host "  Email: $adminEmail" -ForegroundColor White
        Write-Host "  Tier:  $($response.user.tier)" -ForegroundColor White
        Write-Host "  ID:    $($response.user.id)" -ForegroundColor White
        Write-Host ""
        
        $userId = $response.user.id
        $token = $response.token
        
        # Upgrade to Premium tier
        Write-Host "Upgrading to Premium tier..." -ForegroundColor Yellow
        
        $upgradeResponse = Invoke-RestMethod -Uri "http://localhost:8081/api/subscription/upgrade" `
            -Method POST `
            -Headers @{Authorization = "Bearer $token"} `
            -ContentType "application/json" `
            -ErrorAction Stop
        
        if ($upgradeResponse.success) {
            Write-Host "✓ Upgraded to Premium tier!" -ForegroundColor Green
        } else {
            Write-Host "⚠ Failed to upgrade to Premium: $($upgradeResponse.message)" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║          ADMINISTRATOR CREATED! ✓              ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "Login Credentials:" -ForegroundColor Cyan
        Write-Host "  URL:      http://localhost:3000" -ForegroundColor White
        Write-Host "  Email:    $adminEmail" -ForegroundColor White
        Write-Host "  Password: [as entered]" -ForegroundColor White
        Write-Host ""
        Write-Host "Privileges:" -ForegroundColor Cyan
        Write-Host "  ✓ Access to all features" -ForegroundColor Green
        Write-Host "  ✓ Premium tier (scheduled scans, custom directories)" -ForegroundColor Green
        Write-Host "  ✓ Advanced PDF reports" -ForegroundColor Green
        Write-Host "  ✓ Settings management" -ForegroundColor Green
        Write-Host "  ✓ Full system control" -ForegroundColor Green
        Write-Host ""
        
        # Open browser
        Write-Host "Opening Nebula Shield..." -ForegroundColor Cyan
        Start-Process "http://localhost:3000"
        
    } else {
        Write-Host "✗ Failed to create administrator: $($response.message)" -ForegroundColor Red
    }
    
} catch {
    Write-Host ""
    Write-Host "✗ Error creating administrator account:" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow
    
    if ($_.ErrorDetails.Message) {
        $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($errorDetails.message) {
            Write-Host "  $($errorDetails.message)" -ForegroundColor Yellow
        }
        if ($errorDetails.errors) {
            $errorDetails.errors | ForEach-Object {
                Write-Host "  - $($_.msg): $($_.path)" -ForegroundColor Yellow
            }
        }
    }
    
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Cyan
    Write-Host "  1. Make sure auth service is running:" -ForegroundColor White
    Write-Host "     Get-Service NebulaShieldAuth" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. Check if email is already registered" -ForegroundColor White
    Write-Host "     Try logging in instead" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  3. Verify auth server is responding:" -ForegroundColor White
    Write-Host "     Invoke-RestMethod http://localhost:8081/api/auth/verify" -ForegroundColor Gray
}

Write-Host ""
pause
