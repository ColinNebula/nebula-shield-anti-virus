# ====================================
# Configuration Switcher
# ====================================
# Allows easy switching between local and cloud backend

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('local', 'cloud')]
    [string]$Mode,
    
    [Parameter(Mandatory=$false)]
    [string]$CloudUrl = ""
)

$ErrorActionPreference = "Stop"

Write-Host "🔧 Nebula Shield - Configuration Switcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# File paths
$authContextFile = "src/contexts/AuthContext.js"
$scanWorkerFile = "src/workers/scanWorker.js"
$antivirusApiFile = "src/services/antivirusApi.js"
$mobileAuthFile = "mobile/src/services/AuthService.ts"

if ($Mode -eq "cloud") {
    if (-not $CloudUrl) {
        Write-Host "❌ Error: Cloud URL is required when switching to cloud mode" -ForegroundColor Red
        Write-Host "Usage: .\configure-deployment.ps1 -Mode cloud -CloudUrl https://your-backend.railway.app" -ForegroundColor Yellow
        exit 1
    }
    
    # Validate URL format
    if ($CloudUrl -notmatch '^https?://') {
        Write-Host "❌ Error: Cloud URL must start with http:// or https://" -ForegroundColor Red
        exit 1
    }
    
    # Remove trailing slash
    $CloudUrl = $CloudUrl.TrimEnd('/')
    
    Write-Host "☁️  Switching to CLOUD mode..." -ForegroundColor Green
    Write-Host "Backend URL: $CloudUrl" -ForegroundColor Yellow
    
    # Create .env.local for frontend
    $envContent = @"
VITE_API_URL=$CloudUrl
VITE_BACKEND_MODE=cloud
"@
    Set-Content -Path ".env.local" -Value $envContent
    Write-Host "✅ Created .env.local with cloud configuration" -ForegroundColor Green
    
    # Update mobile app config
    if (Test-Path $mobileAuthFile) {
        Write-Host "📱 Updating mobile app configuration..." -ForegroundColor Yellow
        $mobileContent = Get-Content $mobileAuthFile -Raw
        $mobileContent = $mobileContent -replace "const API_URL = .*", "const API_URL = '$CloudUrl/api';"
        Set-Content -Path $mobileAuthFile -Value $mobileContent
        Write-Host "✅ Updated mobile app to use cloud backend" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "⚠️  IMPORTANT NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "1. Deploy backend to cloud (see CLOUD-DEPLOYMENT-GUIDE.md)" -ForegroundColor White
    Write-Host "2. Update backend .env with production values" -ForegroundColor White
    Write-Host "3. Test connection: curl $CloudUrl/api/health" -ForegroundColor White
    Write-Host "4. Rebuild desktop app with: npm run build" -ForegroundColor White
    Write-Host "5. Rebuild mobile app with new API URL" -ForegroundColor White
    
} elseif ($Mode -eq "local") {
    Write-Host "💻 Switching to LOCAL mode..." -ForegroundColor Green
    Write-Host "Backend will run on localhost" -ForegroundColor Yellow
    
    # Remove .env.local
    if (Test-Path ".env.local") {
        Remove-Item ".env.local"
        Write-Host "✅ Removed .env.local" -ForegroundColor Green
    }
    
    # Reset mobile app config
    if (Test-Path $mobileAuthFile) {
        Write-Host "📱 Updating mobile app configuration..." -ForegroundColor Yellow
        $mobileContent = Get-Content $mobileAuthFile -Raw
        # Get local IP for mobile testing
        $localIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*Wi-Fi*" -or $_.InterfaceAlias -like "*Ethernet*" } | Select-Object -First 1).IPAddress
        if ($localIp) {
            $mobileContent = $mobileContent -replace "const API_URL = .*", "const API_URL = Constants.expoConfig?.extra?.apiUrl || 'http://${localIp}:8082/api';"
            Write-Host "✅ Updated mobile app to use local backend at $localIp" -ForegroundColor Green
        } else {
            Write-Host "⚠️  Could not determine local IP address" -ForegroundColor Yellow
        }
        Set-Content -Path $mobileAuthFile -Value $mobileContent
    }
    
    Write-Host ""
    Write-Host "✅ Configuration switched to LOCAL mode" -ForegroundColor Green
    Write-Host ""
    Write-Host "💡 Next steps:" -ForegroundColor Yellow
    Write-Host "1. Start backend: cd backend && npm start" -ForegroundColor White
    Write-Host "2. Start frontend: npm run dev" -ForegroundColor White
    Write-Host "3. For mobile: Ensure your device is on same network" -ForegroundColor White
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Configuration complete! 🎉" -ForegroundColor Green
