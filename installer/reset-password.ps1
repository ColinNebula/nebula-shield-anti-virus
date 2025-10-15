# Reset Password for Nebula Shield User
# Run as Administrator

Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Nebula Shield - Password Reset               ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "⚠ This script should be run as Administrator for database access" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Enter user email and new password:" -ForegroundColor Yellow
Write-Host ""

$email = Read-Host "Email Address"
$newPassword = Read-Host "New Password" -AsSecureString
$newPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPassword)
)

if ($newPasswordPlain.Length -lt 6) {
    Write-Host ""
    Write-Host "✗ Password must be at least 6 characters!" -ForegroundColor Red
    pause
    exit 1
}

Write-Host ""
Write-Host "Resetting password..." -ForegroundColor Yellow
Write-Host ""

# Create Node.js script to update password
$nodeScript = @"
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const email = '$email';
const newPassword = '$newPasswordPlain';
const dbPath = 'C:\\Program Files\\Nebula Shield\\data\\auth.db';

// Hash the new password
bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
    if (err) {
        console.error('Error hashing password:', err);
        process.exit(1);
    }
    
    // Connect to database
    const db = new sqlite3.Database(dbPath, (err) => {
        if (err) {
            console.error('Database error:', err);
            process.exit(1);
        }
        
        // Update password
        db.run('UPDATE users SET password = ? WHERE email = ?',
            [hashedPassword, email],
            function(err) {
                if (err) {
                    console.error('Update error:', err);
                    process.exit(1);
                }
                
                if (this.changes === 0) {
                    console.error('User not found with email:', email);
                    process.exit(1);
                }
                
                console.log('SUCCESS:Password updated for:', email);
                console.log('CHANGES:', this.changes);
                
                db.close();
                process.exit(0);
            }
        );
    });
});
"@

try {
    # Save script to temp file
    $tempScript = [System.IO.Path]::GetTempFileName() + ".js"
    Set-Content -Path $tempScript -Value $nodeScript
    
    # Run Node.js script from auth-server directory
    Push-Location "C:\Program Files\Nebula Shield\auth-server"
    $output = & node $tempScript 2>&1
    Pop-Location
    
    # Clean up
    Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    
    if ($output -match "SUCCESS") {
        Write-Host "✓ Password updated successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "New Credentials:" -ForegroundColor Cyan
        Write-Host "  Email:    $email" -ForegroundColor White
        Write-Host "  Password: [as entered]" -ForegroundColor White
        Write-Host ""
        Write-Host "Login at: http://localhost:3000/login" -ForegroundColor Cyan
        Write-Host ""
        
        $openBrowser = Read-Host "Open login page now? (Y/n)"
        if ($openBrowser -ne 'n' -and $openBrowser -ne 'N') {
            Start-Process "http://localhost:3000/login"
        }
    } else {
        Write-Host "✗ Password reset failed!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Error details:" -ForegroundColor Yellow
        Write-Host $output -ForegroundColor Gray
        Write-Host ""
        
        if ($output -match "User not found") {
            Write-Host "The email address was not found in the database." -ForegroundColor Yellow
            Write-Host "Please check the email or create a new account." -ForegroundColor Yellow
        }
    }
    
} catch {
    Write-Host "✗ Error resetting password:" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Cyan
    Write-Host "  1. Make sure you're running as Administrator" -ForegroundColor White
    Write-Host "  2. Verify the database exists:" -ForegroundColor White
    Write-Host "     C:\Program Files\Nebula Shield\data\auth.db" -ForegroundColor Gray
    Write-Host "  3. Check that Node.js is installed" -ForegroundColor White
}

Write-Host ""
pause
