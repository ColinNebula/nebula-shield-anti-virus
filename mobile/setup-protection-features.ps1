# Nebula Shield Mobile - Setup Script
# Run this to install new dependencies for mobile protection features

Write-Host "🛡️ Nebula Shield Mobile - Installing Protection Features..." -ForegroundColor Cyan
Write-Host ""

# Check if we're in the mobile directory
if (-not (Test-Path "package.json")) {
    Write-Host "❌ Error: package.json not found!" -ForegroundColor Red
    Write-Host "Please run this script from the mobile directory." -ForegroundColor Yellow
    exit 1
}

Write-Host "📦 Installing dependencies..." -ForegroundColor Green
npm install expo-location

Write-Host ""
Write-Host "✅ Installation complete!" -ForegroundColor Green
Write-Host ""

Write-Host "📚 New Mobile Protection Services:" -ForegroundColor Cyan
Write-Host "  ✓ MalwareScannerService - Real-time malware detection" -ForegroundColor White
Write-Host "  ✓ AntiTheftService - Device tracking & remote control" -ForegroundColor White
Write-Host "  ✓ SMSCallProtectionService - Spam & phishing blocking" -ForegroundColor White
Write-Host ""

Write-Host "📖 Documentation:" -ForegroundColor Cyan
Write-Host "  • REAL_MOBILE_PROTECTION_FEATURES.md - Complete feature guide" -ForegroundColor White
Write-Host "  • TESTING_MOBILE_PROTECTION.md - Testing guide" -ForegroundColor White
Write-Host "  • IMPLEMENTATION_SUMMARY.md - Quick overview" -ForegroundColor White
Write-Host ""

Write-Host "🚀 Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Run: npx expo start" -ForegroundColor Yellow
Write-Host "  2. Test the new protection features" -ForegroundColor Yellow
Write-Host "  3. Read the documentation files" -ForegroundColor Yellow
Write-Host ""

Write-Host "🎉 Ready to protect your mobile devices!" -ForegroundColor Green
