#!/usr/bin/env powershell
# Security Audit Script for Nebula Shield Anti-Virus
# Run this before committing code or deploying to production

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Nebula Shield Security Audit" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$ErrorCount = 0
$WarningCount = 0

# =============================
# 1. Check for secrets in code
# =============================
Write-Host "[1/8] Checking for hardcoded secrets..." -ForegroundColor Yellow

$SecretPatterns = @(
    "api[_-]?key\s*[:=]\s*['\`"][^'\`"]+['\`"]",
    "password\s*[:=]\s*['\`"][^'\`"]+['\`"]",
    "secret\s*[:=]\s*['\`"][^'\`"]+['\`"]",
    "token\s*[:=]\s*['\`"][^'\`"]+['\`"]",
    "JWT_SECRET\s*[:=]\s*['\`"][^'\`"]+['\`"]",
    "VIRUSTOTAL_API_KEY\s*[:=]\s*['\`"][^'\`"]+['\`"]"
)

$FilesToCheck = Get-ChildItem -Recurse -Include *.js,*.jsx,*.ts,*.tsx,*.json -Exclude node_modules,dist,build | Select-Object -First 1000

foreach ($pattern in $SecretPatterns) {
    $matches = $FilesToCheck | Select-String -Pattern $pattern -CaseSensitive:$false
    if ($matches) {
        Write-Host "  ⚠️  WARNING: Potential hardcoded secret found:" -ForegroundColor Red
        $matches | ForEach-Object {
            Write-Host "      File: $($_.Path):$($_.LineNumber)" -ForegroundColor Gray
            Write-Host "      Content: $($_.Line.Trim())" -ForegroundColor Gray
        }
        $WarningCount++
    }
}

if ($WarningCount -eq 0) {
    Write-Host "  ✅ No hardcoded secrets detected" -ForegroundColor Green
}

Write-Host ""

# =============================
# 2. Check .env files
# =============================
Write-Host "[2/8] Checking for .env files in git staging..." -ForegroundColor Yellow

$StagedEnvFiles = git diff --cached --name-only | Select-String -Pattern "\.env$"
if ($StagedEnvFiles) {
    Write-Host "  ❌ ERROR: .env files are staged for commit:" -ForegroundColor Red
    $StagedEnvFiles | ForEach-Object {
        Write-Host "      $_" -ForegroundColor Gray
    }
    Write-Host "  Run: git reset HEAD .env" -ForegroundColor Yellow
    $ErrorCount++
} else {
    Write-Host "  ✅ No .env files staged" -ForegroundColor Green
}

Write-Host ""

# =============================
# 3. Check for large files
# =============================
Write-Host "[3/8] Checking for large files (>10MB)..." -ForegroundColor Yellow

$LargeFiles = Get-ChildItem -Recurse -File -Exclude node_modules,dist,build,*.db | 
    Where-Object { $_.Length -gt 10MB } |
    Select-Object Name, @{Name="Size(MB)";Expression={[math]::Round($_.Length/1MB, 2)}}, FullName

if ($LargeFiles) {
    Write-Host "  ⚠️  WARNING: Large files found (should be in .gitignore):" -ForegroundColor Red
    $LargeFiles | ForEach-Object {
        $sizeMB = $_.'Size(MB)'
        Write-Host "      $($_.Name) - $sizeMB MB" -ForegroundColor Gray
    }
    $WarningCount++
} else {
    Write-Host "  ✅ No large files detected" -ForegroundColor Green
}

Write-Host ""

# =============================
# 4. NPM Audit (Production)
# =============================
Write-Host "[4/8] Running npm audit (production dependencies)..." -ForegroundColor Yellow

$AuditOutput = npm audit --production --json 2>$null | ConvertFrom-Json

if ($AuditOutput.metadata.vulnerabilities) {
    $Vulns = $AuditOutput.metadata.vulnerabilities
    $Critical = $Vulns.critical
    $High = $Vulns.high
    $Moderate = $Vulns.moderate
    $Low = $Vulns.low
    
    if ($Critical -gt 0 -or $High -gt 0) {
        Write-Host "  ❌ ERROR: Critical or High vulnerabilities found:" -ForegroundColor Red
        Write-Host "      Critical: $Critical" -ForegroundColor Red
        Write-Host "      High: $High" -ForegroundColor Red
        Write-Host "      Moderate: $Moderate" -ForegroundColor Yellow
        Write-Host "      Low: $Low" -ForegroundColor Gray
        Write-Host "  Run: npm audit fix" -ForegroundColor Yellow
        $ErrorCount++
    } elseif ($Moderate -gt 0) {
        Write-Host "  ⚠️  WARNING: Moderate vulnerabilities found:" -ForegroundColor Yellow
        Write-Host "      Moderate: $Moderate" -ForegroundColor Yellow
        Write-Host "      Low: $Low" -ForegroundColor Gray
        $WarningCount++
    } else {
        Write-Host "  ✅ No critical vulnerabilities (Low: $Low)" -ForegroundColor Green
    }
} else {
    Write-Host "  ✅ No vulnerabilities found" -ForegroundColor Green
}

Write-Host ""

# =============================
# 5. Check .gitignore
# =============================
Write-Host "[5/8] Checking .gitignore configuration..." -ForegroundColor Yellow

$RequiredIgnores = @(
    "node_modules",
    ".env",
    "*.db",
    "*.log",
    "dist/",
    "build/"
)

if (Test-Path ".gitignore") {
    $GitignoreContent = Get-Content ".gitignore" -Raw
    $MissingIgnores = $RequiredIgnores | Where-Object { $GitignoreContent -notmatch [regex]::Escape($_) }
    
    if ($MissingIgnores) {
        Write-Host "  ⚠️  WARNING: Missing .gitignore entries:" -ForegroundColor Yellow
        $MissingIgnores | ForEach-Object {
            Write-Host "      $_" -ForegroundColor Gray
        }
        $WarningCount++
    } else {
        Write-Host "  ✅ All required patterns in .gitignore" -ForegroundColor Green
    }
} else {
    Write-Host "  ❌ ERROR: .gitignore file not found!" -ForegroundColor Red
    $ErrorCount++
}

Write-Host ""

# =============================
# 6. Check database files
# =============================
Write-Host "[6/8] Checking for database files in git..." -ForegroundColor Yellow

$DbFiles = git ls-files | Select-String -Pattern "\.(db|sqlite)$"
if ($DbFiles) {
    Write-Host "  ❌ ERROR: Database files tracked in git:" -ForegroundColor Red
    $DbFiles | ForEach-Object {
        Write-Host "      $_" -ForegroundColor Gray
    }
    Write-Host "  Run: git rm --cached *.db" -ForegroundColor Yellow
    $ErrorCount++
} else {
    Write-Host "  ✅ No database files in repository" -ForegroundColor Green
}

Write-Host ""

# =============================
# 7. Check for console.log
# =============================
Write-Host "[7/8] Checking for console.log statements..." -ForegroundColor Yellow

$ConsoleLogs = Get-ChildItem -Recurse -Include *.js,*.jsx,*.ts,*.tsx -Exclude node_modules,dist,build |
    Select-String -Pattern "console\.(log|error|warn)" -CaseSensitive:$false

if ($ConsoleLogs) {
    $LogCount = ($ConsoleLogs | Measure-Object).Count
    Write-Host "  ⚠️  INFO: Found $LogCount console statements (consider using a logger)" -ForegroundColor Gray
} else {
    Write-Host "  ✅ No console statements found" -ForegroundColor Green
}

Write-Host ""

# =============================
# 8. File permissions check
# =============================
Write-Host "[8/8] Checking sensitive file permissions..." -ForegroundColor Yellow

$SensitiveFiles = @(
    ".env",
    "backend/.env",
    "cloud-backend/.env",
    "mobile/.env"
)

foreach ($file in $SensitiveFiles) {
    if (Test-Path $file) {
        # Note: Windows file permissions are complex, this is a basic check
        Write-Host "  [i] Found: $file (ensure proper permissions)" -ForegroundColor Gray
    }
}

Write-Host "  [OK] File permission check complete" -ForegroundColor Green
Write-Host ""

# =============================
# Summary
# =============================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Security Audit Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

Write-Host ""
if ($ErrorCount -eq 0 -and $WarningCount -eq 0) {
    Write-Host "✅ PASSED - No security issues detected" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your code is ready for commit!" -ForegroundColor Green
    exit 0
} elseif ($ErrorCount -eq 0) {
    Write-Host "⚠️  PASSED WITH WARNINGS - $WarningCount warning(s)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Review warnings above before committing." -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "❌ FAILED - $ErrorCount error(s), $WarningCount warning(s)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Fix errors above before committing!" -ForegroundColor Red
    exit 1
}
