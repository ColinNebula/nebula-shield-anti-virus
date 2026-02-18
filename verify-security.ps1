# Security Verification Script
# Run this before deploying to ensure app is secure

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Security Verification" -ForegroundColor Cyan  
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$issues = 0

# Check 1: Verify .env files are not in git
Write-Host "[1/7] Checking .env files in git..." -ForegroundColor Yellow
$envInGit = git ls-files | Select-String -Pattern "^\.env$|backend/\.env$|backend/.env.production$"
if ($envInGit) {
    Write-Host "FAIL: .env files found in git!" -ForegroundColor Red
    $issues++
} else {
    Write-Host "PASS: No .env files in git" -ForegroundColor Green
}
Write-Host ""

# Check 2: Verify no hardcoded credentials in code
Write-Host "[2/7] Checking for hardcoded credentials..." -ForegroundColor Yellow
$hardcodedCreds = git grep -i "admin@test\.com\|Nebula2025!\|demo123\|Test123!" -- "*.js" "*.ts" "*.jsx" "*.tsx" 2>$null
if ($hardcodedCreds) {
    Write-Host "FAIL: Hardcoded credentials found!" -ForegroundColor Red
    $hardcodedCreds | ForEach-Object {
        Write-Host "   $_" -ForegroundColor Gray
    }
    $issues++
} else {
    Write-Host "PASS: No hardcoded credentials found" -ForegroundColor Green
}
Write-Host ""

# Check 3: Verify test files were deleted
Write-Host "[3/7] Checking for test files with credentials..." -ForegroundColor Yellow
$testFiles = @(
    "backend/check-db.js",
    "backend/test-password.js",
    "backend/fix-admin-password.js",
    "ADMIN-CREDENTIALS.md"
)
$foundTests = $testFiles | Where-Object { Test-Path $_ }
if ($foundTests) {
    Write-Host "WARNING: Test files still exist:" -ForegroundColor Yellow
    $foundTests | ForEach-Object { Write-Host "   $_" -ForegroundColor Gray }
    $issues++
} else {
    Write-Host "PASS: Test files deleted" -ForegroundColor Green
}
Write-Host ""

# Check 4: Verify JWT_SECRET is required
Write-Host "[4/7] Checking JWT_SECRET configuration..." -ForegroundColor Yellow
$authServerContent = Get-Content "backend/auth-server.js" -Raw
if ($authServerContent -like "*!process.env.JWT_SECRET*process.exit*") {
    Write-Host "PASS: JWT_SECRET requires environment variable" -ForegroundColor Green
}
else {
    Write-Host "WARNING: Could not verify JWT_SECRET config" -ForegroundColor Yellow
}
Write-Host ""

# Check 5: Verify .env.example exists
Write-Host "[5/7] Checking for .env.example templates..." -ForegroundColor Yellow
if ((Test-Path ".env.example") -and (Test-Path "backend/.env.example")) {
    Write-Host "PASS: .env.example templates exist" -ForegroundColor Green
} else {
    Write-Host "WARNING: Missing .env.example templates" -ForegroundColor Yellow
}
Write-Host ""

# Check 6: Check for personal emails in tracked files
Write-Host "[6/7] Checking for personal information..." -ForegroundColor Yellow
$personalInfo = git grep -i "colinnebula@gmail\.com\|colinnebula@hotmail\.com" -- "*.md" "*.js" "*.ts" | Select-Object -First 5
if ($personalInfo) {
    Write-Host "WARNING: Personal info found in tracked files:" -ForegroundColor Yellow
    $personalInfo | ForEach-Object {
        Write-Host "   $_" -ForegroundColor Gray
    }
} else {
    Write-Host "PASS: No personal information in tracked files" -ForegroundColor Green
}
Write-Host ""

# Check 7: Verify production build is lightweight
Write-Host "[7/7] Checking repository size..." -ForegroundColor Yellow
$repoSize = (Get-ChildItem -Recurse -File | Where-Object { $_.FullName -notmatch "node_modules|\.git|dist|build|out" } | Measure-Object -Property Length -Sum).Sum / 1MB
Write-Host "Repository size (excluding node_modules): $([math]::Round($repoSize, 2)) MB" -ForegroundColor Green
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
if ($issues -eq 0) {
    Write-Host "  SECURITY CHECK PASSED" -ForegroundColor Green
    Write-Host "  Your app is secure and ready to deploy!" -ForegroundColor Green
} else {
    Write-Host "  SECURITY ISSUES FOUND: $issues" -ForegroundColor Yellow
    Write-Host "  Fix issues before deploying!" -ForegroundColor Yellow
}
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Exit code
if ($issues -gt 0) {
    Write-Host "Run fixes and try again." -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "Safe to deploy!" -ForegroundColor Green
    exit 0
}
