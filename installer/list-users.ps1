# List All Users in Nebula Shield
# Run as Administrator

Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Nebula Shield - List All Users               ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$dbPath = "C:\Program Files\Nebula Shield\data\auth.db"

if (-not (Test-Path $dbPath)) {
    Write-Host "✗ Database not found at: $dbPath" -ForegroundColor Red
    pause
    exit 1
}

Write-Host "Fetching users..." -ForegroundColor Yellow
Write-Host ""

# Create Node.js script to query users
$nodeScript = @"
const sqlite3 = require('sqlite3').verbose();
const dbPath = 'C:\\Program Files\\Nebula Shield\\data\\auth.db';

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Database error:', err);
        process.exit(1);
    }
    
    // Get all users with their subscription info
    db.all(`
        SELECT 
            u.id,
            u.email,
            u.full_name,
            u.created_at,
            COALESCE(s.tier, 'free') as tier,
            COALESCE(s.status, 'active') as status
        FROM users u
        LEFT JOIN subscriptions s ON u.id = s.user_id
        ORDER BY u.id
    `, [], (err, rows) => {
        if (err) {
            console.error('Query error:', err);
            process.exit(1);
        }
        
        console.log('USERS:' + JSON.stringify(rows));
        db.close();
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
    
    if ($output -match "USERS:") {
        $jsonData = $output -replace ".*USERS:", ""
        $users = $jsonData | ConvertFrom-Json
        
        if ($users.Count -eq 0) {
            Write-Host "No users found in database." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Create a new admin account with:" -ForegroundColor Cyan
            Write-Host "  .\admin-manager.ps1" -ForegroundColor White
        } else {
            Write-Host "Registered Users ($($users.Count)):" -ForegroundColor Green
            Write-Host ""
            Write-Host ("=" * 80) -ForegroundColor Gray
            
            foreach ($user in $users) {
                $tierColor = if ($user.tier -eq 'premium') { 'Yellow' } else { 'White' }
                $statusColor = if ($user.status -eq 'active') { 'Green' } else { 'Red' }
                
                Write-Host "ID:       " -NoNewline -ForegroundColor Gray
                Write-Host $user.id -ForegroundColor White
                
                Write-Host "Name:     " -NoNewline -ForegroundColor Gray
                Write-Host $user.full_name -ForegroundColor White
                
                Write-Host "Email:    " -NoNewline -ForegroundColor Gray
                Write-Host $user.email -ForegroundColor Cyan
                
                Write-Host "Tier:     " -NoNewline -ForegroundColor Gray
                Write-Host $user.tier.ToUpper() -ForegroundColor $tierColor
                
                Write-Host "Status:   " -NoNewline -ForegroundColor Gray
                Write-Host $user.status -ForegroundColor $statusColor
                
                Write-Host "Created:  " -NoNewline -ForegroundColor Gray
                Write-Host $user.created_at -ForegroundColor White
                
                Write-Host ("=" * 80) -ForegroundColor Gray
            }
            
            Write-Host ""
            Write-Host "Management Options:" -ForegroundColor Cyan
            Write-Host "  Reset Password:  .\reset-password.ps1" -ForegroundColor White
            Write-Host "  Create Admin:    .\admin-manager.ps1" -ForegroundColor White
            Write-Host "  Upgrade to Premium: .\admin-manager.ps1 (option 2)" -ForegroundColor White
        }
    } else {
        Write-Host "✗ Failed to fetch users" -ForegroundColor Red
        Write-Host "Output: $output" -ForegroundColor Gray
    }
    
} catch {
    Write-Host "✗ Error:" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
pause
