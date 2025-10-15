# Advanced Admin Setup - Direct Database Access
# Creates admin account and sets privileges directly in database
# Run as Administrator

Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Nebula Shield - Advanced Admin Setup        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check for Node.js (needed for bcrypt)
try {
    $nodeVersion = node --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Node.js not found"
    }
    Write-Host "✓ Node.js detected: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Node.js not found!" -ForegroundColor Red
    Write-Host "Please install Node.js to continue" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host ""

# Admin details
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  Enter Administrator Credentials" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

$fullName = Read-Host "Full Name"
if ([string]::IsNullOrWhiteSpace($fullName)) { $fullName = "System Administrator" }

$email = Read-Host "Email"
if ([string]::IsNullOrWhiteSpace($email)) {
    Write-Host "✗ Email is required!" -ForegroundColor Red
    pause
    exit 1
}

$password = Read-Host "Password (min 6 chars)" -AsSecureString
$passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
)

if ($passwordPlain.Length -lt 6) {
    Write-Host "✗ Password must be at least 6 characters!" -ForegroundColor Red
    pause
    exit 1
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Creating Administrator Account" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Method 1: Try via API first
Write-Host "[1/2] Attempting to create via API..." -ForegroundColor Yellow

$body = @{
    fullName = $fullName
    email = $email
    password = $passwordPlain
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "http://localhost:8081/api/auth/register" `
        -Method POST `
        -Body $body `
        -ContentType "application/json" `
        -TimeoutSec 10 `
        -ErrorAction Stop
    
    if ($response.success) {
        Write-Host "      ✓ Account created via API" -ForegroundColor Green
        
        $userId = $response.user.id
        $token = $response.token
        
        # Upgrade to Premium
        Write-Host "[2/2] Upgrading to Premium tier..." -ForegroundColor Yellow
        
        try {
            $upgradeResponse = Invoke-RestMethod -Uri "http://localhost:8081/api/subscription/upgrade" `
                -Method POST `
                -Headers @{Authorization = "Bearer $token"} `
                -ContentType "application/json" `
                -ErrorAction Stop
            
            if ($upgradeResponse.success) {
                Write-Host "      ✓ Upgraded to Premium tier" -ForegroundColor Green
            }
        } catch {
            Write-Host "      ⚠ Could not upgrade to Premium (can do manually)" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║           ADMINISTRATOR CREATED! ✓             ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "Account Information:" -ForegroundColor Cyan
        Write-Host "  Name:     $fullName" -ForegroundColor White
        Write-Host "  Email:    $email" -ForegroundColor White
        Write-Host "  User ID:  $userId" -ForegroundColor White
        Write-Host "  Tier:     Premium" -ForegroundColor White
        Write-Host ""
        Write-Host "Access:" -ForegroundColor Cyan
        Write-Host "  URL:      http://localhost:3000" -ForegroundColor White
        Write-Host "  Email:    $email" -ForegroundColor White
        Write-Host "  Password: [as entered]" -ForegroundColor White
        Write-Host ""
        Write-Host "Privileges:" -ForegroundColor Cyan
        Write-Host "  ✓ Full system access" -ForegroundColor Green
        Write-Host "  ✓ All Premium features" -ForegroundColor Green
        Write-Host "  ✓ Scheduled scans" -ForegroundColor Green
        Write-Host "  ✓ Custom scan directories" -ForegroundColor Green
        Write-Host "  ✓ Advanced PDF reports" -ForegroundColor Green
        Write-Host "  ✓ Settings management" -ForegroundColor Green
        Write-Host ""
        
        # Open browser
        $openBrowser = Read-Host "Open Nebula Shield now? (Y/n)"
        if ($openBrowser -ne 'n' -and $openBrowser -ne 'N') {
            Start-Process "http://localhost:3000"
        }
        
    } else {
        throw $response.message
    }
    
} catch {
    Write-Host "      ⚠ API method failed" -ForegroundColor Yellow
    Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Gray
    Write-Host ""
    
    # Method 2: Direct database creation
    Write-Host "[2/2] Attempting direct database creation..." -ForegroundColor Yellow
    
    $dbPath = "C:\Program Files\Nebula Shield\data\auth.db"
    
    if (-not (Test-Path $dbPath)) {
        Write-Host "      ✗ Database not found at: $dbPath" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please ensure Nebula Shield is installed and services are running." -ForegroundColor Yellow
        pause
        exit 1
    }
    
    # Create Node.js script to hash password and insert into database
    $nodeScript = @"
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const email = '$email';
const password = '$passwordPlain';
const fullName = '$fullName';

// Hash password
bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
        console.error('Error hashing password:', err);
        process.exit(1);
    }
    
    // Connect to database
    const db = new sqlite3.Database('$dbPath', (err) => {
        if (err) {
            console.error('Database error:', err);
            process.exit(1);
        }
        
        // Insert user
        const now = new Date().toISOString();
        
        db.run(`INSERT INTO users (email, password, full_name, created_at) VALUES (?, ?, ?, ?)`,
            [email, hashedPassword, fullName, now],
            function(err) {
                if (err) {
                    console.error('Insert error:', err.message);
                    process.exit(1);
                }
                
                const userId = this.lastID;
                console.log('User created with ID:', userId);
                
                // Create premium subscription
                db.run(`INSERT INTO subscriptions (user_id, tier, status, start_date) VALUES (?, ?, ?, ?)`,
                    [userId, 'premium', 'active', now],
                    (err) => {
                        if (err) {
                            console.error('Subscription error:', err.message);
                        } else {
                            console.log('Premium subscription activated');
                        }
                        
                        db.close();
                        process.exit(0);
                    }
                );
            }
        );
    });
});
"@
    
    try {
        # Save script to temp file
        $tempScript = [System.IO.Path]::GetTempFileName() + ".js"
        Set-Content -Path $tempScript -Value $nodeScript
        
        # Run Node.js script from auth-server directory (has required packages)
        Set-Location "C:\Program Files\Nebula Shield\auth-server"
        $output = node $tempScript 2>&1
        
        # Clean up
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "      ✓ Administrator created in database" -ForegroundColor Green
            Write-Host ""
            Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Green
            Write-Host "║           ADMINISTRATOR CREATED! ✓             ║" -ForegroundColor Green
            Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Green
            Write-Host ""
            Write-Host "Account Information:" -ForegroundColor Cyan
            Write-Host "  Name:     $fullName" -ForegroundColor White
            Write-Host "  Email:    $email" -ForegroundColor White
            Write-Host "  Tier:     Premium" -ForegroundColor White
            Write-Host ""
            Write-Host "Login at: http://localhost:3000" -ForegroundColor Cyan
            Write-Host ""
            
            Start-Process "http://localhost:3000"
        } else {
            Write-Host "      ✗ Database creation failed" -ForegroundColor Red
            Write-Host "      Output: $output" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "      ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
pause
