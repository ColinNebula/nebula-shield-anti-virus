# ═══════════════════════════════════════════════════════════
# Nebula Shield - Test Built Application
# Tests the built standalone application locally
# ═══════════════════════════════════════════════════════════

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Nebula Shield - Test Built Application                ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if dist folder exists
if (-not (Test-Path "dist")) {
    Write-Host "❌ No 'dist' folder found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please build the application first:" -ForegroundColor Yellow
    Write-Host "   .\BUILD-STANDALONE.bat" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

# Find built files
Write-Host "🔍 Searching for built applications..." -ForegroundColor Yellow
Write-Host ""

$portable = Get-ChildItem -Path "dist" -Filter "*Portable*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
$installer = Get-ChildItem -Path "dist" -Filter "*Setup*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
$unpacked = Get-ChildItem -Path "dist\win-unpacked" -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1

# Show options
Write-Host "Available test options:" -ForegroundColor Cyan
Write-Host ""

$options = @()
$optionNum = 1

if ($portable) {
    Write-Host "  [$optionNum] Portable Version" -ForegroundColor Green
    Write-Host "      File: $($portable.Name)" -ForegroundColor Gray
    Write-Host "      Size: $([math]::Round($portable.Length / 1MB, 2)) MB" -ForegroundColor Gray
    Write-Host "      Path: $($portable.FullName)" -ForegroundColor Gray
    Write-Host ""
    $options += @{ Number = $optionNum; Type = "Portable"; Path = $portable.FullName }
    $optionNum++
}

if ($installer) {
    Write-Host "  [$optionNum] Installer (will install to system)" -ForegroundColor Yellow
    Write-Host "      File: $($installer.Name)" -ForegroundColor Gray
    Write-Host "      Size: $([math]::Round($installer.Length / 1MB, 2)) MB" -ForegroundColor Gray
    Write-Host "      Path: $($installer.FullName)" -ForegroundColor Gray
    Write-Host ""
    $options += @{ Number = $optionNum; Type = "Installer"; Path = $installer.FullName }
    $optionNum++
}

if ($unpacked) {
    Write-Host "  [$optionNum] Unpacked Version (dev testing)" -ForegroundColor Cyan
    Write-Host "      File: $($unpacked.Name)" -ForegroundColor Gray
    Write-Host "      Path: $($unpacked.FullName)" -ForegroundColor Gray
    Write-Host ""
    $options += @{ Number = $optionNum; Type = "Unpacked"; Path = $unpacked.FullName }
    $optionNum++
}

if ($options.Count -eq 0) {
    Write-Host "❌ No built applications found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please build first:" -ForegroundColor Yellow
    Write-Host "   .\BUILD-STANDALONE.bat" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

Write-Host "  [0] Cancel" -ForegroundColor Gray
Write-Host ""

# Get user choice
$choice = Read-Host "Select option to test"

if ($choice -eq "0" -or $choice -eq "") {
    Write-Host "Cancelled." -ForegroundColor Gray
    exit 0
}

$selected = $options | Where-Object { $_.Number -eq [int]$choice }

if (-not $selected) {
    Write-Host "❌ Invalid selection!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "🚀 Launching $($selected.Type) version..." -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

Write-Host "📋 Testing Instructions:" -ForegroundColor Yellow
Write-Host "   1. Wait for application to load (~5-10 seconds)" -ForegroundColor White
Write-Host "   2. Watch for backend server startup messages" -ForegroundColor White
Write-Host "   3. Login with:" -ForegroundColor White
Write-Host "      Email: admin@test.com" -ForegroundColor Cyan
Write-Host "      Password: admin" -ForegroundColor Cyan
Write-Host "   4. Test key features:" -ForegroundColor White
Write-Host "      • Dashboard loads" -ForegroundColor Gray
Write-Host "      • Settings can be changed" -ForegroundColor Gray
Write-Host "      • Theme toggle works" -ForegroundColor Gray
Write-Host "      • Scan buttons respond" -ForegroundColor Gray
Write-Host "   5. Check DevTools Console for errors" -ForegroundColor White
Write-Host "      (View → Toggle Developer Tools)" -ForegroundColor Gray
Write-Host ""

if ($selected.Type -eq "Installer") {
    Write-Host "⚠️  WARNING: This will INSTALL the application!" -ForegroundColor Yellow
    Write-Host "   • You'll need to uninstall it later" -ForegroundColor Yellow
    Write-Host "   • Use Portable version for quick testing" -ForegroundColor Yellow
    Write-Host ""
    $confirm = Read-Host "Continue with installation? (y/N)"
    if ($confirm -ne "y" -and $confirm -ne "Y") {
        Write-Host "Cancelled." -ForegroundColor Gray
        exit 0
    }
}

Write-Host ""
Write-Host "Starting application..." -ForegroundColor Cyan
Write-Host ""

# Start the application
try {
    Start-Process -FilePath $selected.Path
    Write-Host "✅ Application launched!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Monitor for:" -ForegroundColor Yellow
    Write-Host "   • Backend servers starting (check logs)" -ForegroundColor White
    Write-Host "   • Login page appears" -ForegroundColor White
    Write-Host "   • No error messages" -ForegroundColor White
    Write-Host ""
    Write-Host "If you encounter issues, check:" -ForegroundColor Yellow
    Write-Host "   • Log file: %APPDATA%\Nebula Shield Anti-Virus\electron.log" -ForegroundColor Gray
    Write-Host "   • Ports 8080, 8082 are available" -ForegroundColor Gray
    Write-Host "   • Windows Firewall permissions" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "❌ Failed to launch: $_" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# Offer to check backend health
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
$checkHealth = Read-Host "Check backend server health after startup? (Y/n)"

if ($checkHealth -ne "n" -and $checkHealth -ne "N") {
    Write-Host ""
    Write-Host "⏳ Waiting 10 seconds for backend to start..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    
    Write-Host ""
    Write-Host "🔍 Checking backend servers..." -ForegroundColor Cyan
    Write-Host ""
    
    # Check Mock Backend
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8080/api/status" -TimeoutSec 5 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            Write-Host "   ✅ Mock Backend (8080): RUNNING" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Mock Backend (8080): Unexpected status $($response.StatusCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   ❌ Mock Backend (8080): NOT RESPONDING" -ForegroundColor Red
    }
    
    # Check Auth Server
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8082/api/auth/status" -TimeoutSec 5 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            Write-Host "   ✅ Auth Server (8082): RUNNING" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Auth Server (8082): Unexpected status $($response.StatusCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   ❌ Auth Server (8082): NOT RESPONDING" -ForegroundColor Red
    }
    
    Write-Host ""
}

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "✅ Test session started!" -ForegroundColor Green
Write-Host ""
Write-Host "Happy testing! 🚀" -ForegroundColor White
Write-Host ""
