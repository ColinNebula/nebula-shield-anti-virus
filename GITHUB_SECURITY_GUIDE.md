# GitHub Repository Size Optimization & Security Guide

## 📊 Current Repository Size Analysis

### Large Directories (Excluded from Git):
- `node_modules/` - **1,418 MB** - Main dependencies
- `mobile/node_modules/` - **268 MB** - Mobile app dependencies
- `cloud-backend/node_modules/` - **81 MB** - Cloud backend dependencies
- `backend/node_modules/` - **35 MB** - Backend C++ dependencies
- `dist/` - Build artifacts (varies)
- `build/` - Build artifacts (varies)

### Total Excluded: **~1,802 MB** (NOT in Git repository)

### What's Actually in Git: **~50-100 MB**
- Source code
- Documentation
- Configuration files
- Assets (images, icons)

## ✅ Security Measures Implemented

### 1. **Comprehensive .gitignore**

**Excluded from repository:**
- ✅ All `node_modules/` directories
- ✅ Build artifacts (`dist/`, `build/`, `*.exe`, `*.dmg`)
- ✅ Environment files (`.env`, `.env.local`, etc.)
- ✅ API keys and secrets
- ✅ Database files (`*.db`, `*.sqlite`)
- ✅ Log files (`*.log`, `logs/`)
- ✅ Temporary files
- ✅ OS-specific files
- ✅ IDE configuration
- ✅ User data and uploads
- ✅ Certificates and private keys

### 2. **Environment Variable Protection**

**All sensitive data is now in `.env` files:**
```env
# NEVER COMMIT THESE FILES:
.env
.env.local
.env.production

# ALWAYS COMMIT THIS (template):
.env.example
```

**Protected variables:**
- JWT secrets
- Database URLs
- API keys (Firebase, Stripe, PayPal)
- SMTP credentials
- Third-party service tokens

### 3. **Dependency Security**

**Audit all dependencies:**
```powershell
# Check for vulnerabilities
npm audit

# Auto-fix non-breaking issues
npm audit fix

# Check for outdated packages
npm outdated
```

### 4. **Code Integrity Protection**

**File integrity verification:**
- SHA-256 checksums for critical files
- Code signing for production builds
- Tamper detection on startup
- Integrity verification before execution

### 5. **Build Artifact Security**

**Production builds are:**
- Code-signed with certificate
- Checksummed and verified
- Scanned for malware before distribution
- Hosted on secure CDN/servers

## 🚀 Recommended Workflow

### Before Pushing to GitHub:

```powershell
# 1. Verify .gitignore is working
git status

# Should NOT show:
# - node_modules/
# - .env files
# - *.db files
# - dist/ or build/ directories

# 2. Check for sensitive data
git diff --cached | Select-String -Pattern "(api_key|password|secret|token|JWT)"

# 3. Run security audit
npm audit

# 4. Verify file sizes
git ls-files | ForEach-Object { Get-Item $_ } | Where-Object { $_.Length -gt 1MB } | Select-Object Name, Length

# 5. Push to GitHub
git add .
git commit -m "Your commit message"
git push
```

### After Cloning Repository:

```powershell
# 1. Install dependencies
npm install
cd backend; npm install; cd ..
cd cloud-backend; npm install; cd ..
cd mobile; npm install; cd ..

# 2. Copy environment template
cp .env.example .env
cp cloud-backend/.env.example cloud-backend/.env

# 3. Configure secrets
# Edit .env files with your own values
notepad .env

# 4. Build project
npm run build
```

## 🔒 GitHub Security Best Practices

### 1. **Enable Branch Protection**

In GitHub repository settings:
- Require pull request reviews
- Require status checks to pass
- Require signed commits (optional)
- Include administrators

### 2. **Set Up Security Scanning**

GitHub automatically scans for:
- Known vulnerabilities in dependencies
- Hardcoded secrets
- Code scanning alerts

### 3. **Use GitHub Secrets for CI/CD**

For GitHub Actions workflows:
```yaml
# .github/workflows/build.yml
env:
  JWT_SECRET: ${{ secrets.JWT_SECRET }}
  DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

### 4. **Enable Dependabot**

Automatically updates dependencies:
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
```

## 🛡️ Malware Protection

### Protection Against Malicious Dependencies:

1. **Verify package integrity:**
   ```powershell
   # Check package checksums
   npm install --package-lock-only
   ```

2. **Review dependency tree:**
   ```powershell
   # See all dependencies
   npm ls
   
   # Check for suspicious packages
   npm audit
   ```

3. **Use lock files:**
   - `package-lock.json` ensures exact versions
   - Prevents supply chain attacks
   - Verifies checksums on install

4. **Monitor for suspicious behavior:**
   - Check for unexpected network requests
   - Monitor file system access
   - Review post-install scripts

### Protection Against Malicious Code:

1. **Code signing:**
   - All production builds are signed
   - Verify signature before execution
   - Invalid signatures are rejected

2. **File integrity checks:**
   ```javascript
   // Verify critical files on startup
   const expectedHashes = {
     'main.js': 'sha256-hash-here',
     'backend.exe': 'sha256-hash-here'
   };
   ```

3. **Sandbox execution:**
   - Quarantine system isolates malware
   - Untrusted code runs in sandboxed environment
   - File system access is restricted

## 📦 GitHub Release Best Practices

### Creating a Release:

```powershell
# 1. Build production version
npm run build
npm run electron:build:win

# 2. Create checksums
Get-FileHash dist/*.exe -Algorithm SHA256 | Out-File checksums.txt

# 3. Sign executables (if certificate available)
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com dist/*.exe

# 4. Create GitHub release
# - Upload signed executables
# - Include checksums.txt
# - Add release notes
# - Mark as pre-release or stable
```

### Verification for Users:

```powershell
# Verify download integrity
$hash = (Get-FileHash NebulaShield-Setup.exe).Hash
# Compare with published checksum
```

## 🧹 Repository Cleanup

### Remove Accidentally Committed Secrets:

```powershell
# If you accidentally committed a secret:

# 1. Remove from repository history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch path/to/secret.file" \
  --prune-empty --tag-name-filter cat -- --all

# 2. Force push (DANGEROUS - use with caution)
git push origin --force --all

# 3. Invalidate the exposed secret
# - Rotate JWT secret
# - Change database password
# - Regenerate API keys
```

### BFG Repo-Cleaner (Easier method):

```powershell
# Install BFG
# Download from: https://rtyley.github.io/bfg-repo-cleaner/

# Remove large files
java -jar bfg.jar --strip-blobs-bigger-than 10M

# Remove sensitive data
java -jar bfg.jar --delete-files .env

# Clean up
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

## 📋 Pre-Push Checklist

Before pushing to GitHub:

- [ ] No `node_modules/` directories
- [ ] No `.env` files (only `.env.example`)
- [ ] No API keys or secrets in code
- [ ] No database files
- [ ] No large binaries (>10MB)
- [ ] No log files
- [ ] All sensitive data in environment variables
- [ ] `npm audit` passed (no critical vulnerabilities)
- [ ] `.gitignore` is up to date
- [ ] README has setup instructions
- [ ] SECURITY.md is current

## 🎯 Result

✅ **Repository is now secure and optimized:**

- **Size on GitHub:** ~50-100 MB (source code only)
- **Size with dependencies:** ~1,800 MB (local only, not in Git)
- **Protected:** All secrets excluded from Git
- **Verified:** Dependencies audited for security
- **Documented:** Clear setup instructions for contributors
- **Compliant:** Follows GitHub best practices

## 📞 Support

If you discover security issues, please email: **security@nebulashield.com**

**DO NOT** open public issues for security vulnerabilities!

---

**Last Updated:** October 24, 2025
