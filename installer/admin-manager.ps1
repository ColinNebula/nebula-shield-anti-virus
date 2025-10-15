# Nebula Shield - Administrator Management
# Manage admin accounts, privileges, and subscriptions

Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Nebula Shield - Admin Management             ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

function Show-Menu {
    Write-Host "Select an option:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Create new administrator" -ForegroundColor White
    Write-Host "  [2] Upgrade existing user to Premium" -ForegroundColor White
    Write-Host "  [3] List all users" -ForegroundColor White
    Write-Host "  [4] Login to existing account" -ForegroundColor White
    Write-Host "  [Q] Quit" -ForegroundColor Gray
    Write-Host ""
}

function Create-Admin {
    Write-Host ""
    Write-Host "═══ Create Administrator Account ═══" -ForegroundColor Cyan
    Write-Host ""
    
    $name = Read-Host "Full Name"
    $email = Read-Host "Email"
    $pass = Read-Host "Password" -AsSecureString
    $passPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)
    )
    
    if ($passPlain.Length -lt 6) {
        Write-Host ""
        Write-Host "✗ Password must be at least 6 characters!" -ForegroundColor Red
        return
    }
    
    $body = @{
        fullName = $name
        email = $email
        password = $passPlain
    } | ConvertTo-Json
    
    Write-Host ""
    Write-Host "Creating account..." -ForegroundColor Yellow
    
    try {
        $resp = Invoke-RestMethod -Uri "http://localhost:8081/api/auth/register" `
            -Method POST `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop
        
        if ($resp.success) {
            Write-Host "✓ Account created!" -ForegroundColor Green
            Write-Host "  User ID: $($resp.user.id)" -ForegroundColor Gray
            Write-Host "  Email: $($resp.user.email)" -ForegroundColor Gray
            Write-Host "  Tier: $($resp.user.tier)" -ForegroundColor Gray
            
            # Auto-upgrade to Premium
            Write-Host ""
            Write-Host "Upgrading to Premium..." -ForegroundColor Yellow
            
            $token = $resp.token
            try {
                $upgradeResp = Invoke-RestMethod -Uri "http://localhost:8081/api/subscription/upgrade" `
                    -Method POST `
                    -Headers @{Authorization = "Bearer $token"} `
                    -ContentType "application/json" `
                    -ErrorAction Stop
                
                if ($upgradeResp.success) {
                    Write-Host "✓ Upgraded to Premium!" -ForegroundColor Green
                }
            } catch {
                Write-Host "⚠ Could not upgrade to Premium" -ForegroundColor Yellow
            }
            
            Write-Host ""
            Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Green
            Write-Host "║         ADMINISTRATOR CREATED! ✓               ║" -ForegroundColor Green
            Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Green
            Write-Host ""
            Write-Host "Login at: http://localhost:3000" -ForegroundColor Cyan
            Write-Host "Email: $email" -ForegroundColor White
            Write-Host ""
        }
    } catch {
        Write-Host ""
        Write-Host "✗ Failed to create account" -ForegroundColor Red
        if ($_.ErrorDetails.Message) {
            $error = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Host "  $($error.message)" -ForegroundColor Yellow
        } else {
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Upgrade-UserToPremium {
    Write-Host ""
    Write-Host "═══ Upgrade User to Premium ═══" -ForegroundColor Cyan
    Write-Host ""
    
    $email = Read-Host "User Email"
    $pass = Read-Host "Password" -AsSecureString
    $passPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)
    )
    
    $body = @{
        email = $email
        password = $passPlain
    } | ConvertTo-Json
    
    Write-Host ""
    Write-Host "Logging in..." -ForegroundColor Yellow
    
    try {
        $loginResp = Invoke-RestMethod -Uri "http://localhost:8081/api/auth/login" `
            -Method POST `
            -Body $body `
            -ContentType "application/json" `
            -ErrorAction Stop
        
        if ($loginResp.success) {
            Write-Host "✓ Logged in" -ForegroundColor Green
            
            $token = $loginResp.token
            
            Write-Host "Upgrading to Premium..." -ForegroundColor Yellow
            
            $upgradeResp = Invoke-RestMethod -Uri "http://localhost:8081/api/subscription/upgrade" `
                -Method POST `
                -Headers @{Authorization = "Bearer $token"} `
                -ContentType "application/json" `
                -ErrorAction Stop
            
            if ($upgradeResp.success) {
                Write-Host "✓ Upgraded to Premium!" -ForegroundColor Green
                Write-Host ""
                Write-Host "Premium Features Unlocked:" -ForegroundColor Cyan
                Write-Host "  ✓ Scheduled scans" -ForegroundColor Green
                Write-Host "  ✓ Custom scan directories" -ForegroundColor Green
                Write-Host "  ✓ Advanced PDF reports" -ForegroundColor Green
                Write-Host "  ✓ Priority support" -ForegroundColor Green
                Write-Host ""
            }
        }
    } catch {
        Write-Host ""
        Write-Host "✗ Operation failed" -ForegroundColor Red
        if ($_.ErrorDetails.Message) {
            $error = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Host "  $($error.message)" -ForegroundColor Yellow
        } else {
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function List-AllUsers {
    Write-Host ""
    Write-Host "═══ Registered Users ═══" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Note: Requires direct database access" -ForegroundColor Gray
    Write-Host "Database: C:\Program Files\Nebula Shield\data\auth.db" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To view users, run:" -ForegroundColor Yellow
    Write-Host '  sqlite3 "C:\Program Files\Nebula Shield\data\auth.db" "SELECT id, email, full_name, created_at FROM users;"' -ForegroundColor White
    Write-Host ""
}

function Login-ToAccount {
    Write-Host ""
    Write-Host "Opening login page..." -ForegroundColor Cyan
    Start-Process "http://localhost:3000/login"
    Write-Host "✓ Browser opened" -ForegroundColor Green
    Write-Host ""
}

# Main loop
do {
    Show-Menu
    $choice = Read-Host "Choice"
    
    switch ($choice.ToUpper()) {
        '1' { Create-Admin }
        '2' { Upgrade-UserToPremium }
        '3' { List-AllUsers }
        '4' { Login-ToAccount }
        'Q' { 
            Write-Host ""
            Write-Host "Goodbye!" -ForegroundColor Cyan
            break
        }
        default {
            Write-Host ""
            Write-Host "Invalid choice" -ForegroundColor Red
        }
    }
    
    if ($choice.ToUpper() -ne 'Q') {
        Write-Host ""
        Read-Host "Press Enter to continue"
        Clear-Host
        Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║   Nebula Shield - Admin Management             ║" -ForegroundColor Cyan
        Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
    }
    
} while ($choice.ToUpper() -ne 'Q')
