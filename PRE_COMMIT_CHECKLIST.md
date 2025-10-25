# 📋 Pre-Commit Security Checklist

## ✅ Automated Security Checks

Run these commands **before every commit**:

### 1. Comprehensive Security Audit
```powershell
npm run security:check
```

This runs:
- ✅ Secret scanning (API keys, passwords, tokens)
- ✅ .env file detection in git staging
- ✅ Large file detection (>10MB)
- ✅ NPM vulnerability scan (production dependencies)
- ✅ .gitignore verification
- ✅ Database file detection in git
- ✅ File permission checks

### 2. Quick Security Scan
```powershell
npm run security:audit:production
```

Scans only production dependencies for vulnerabilities.

### 3. File Integrity Check
```powershell
npm run integrity:verify
```

Verifies that critical application files haven't been tampered with.

---

## 📝 Manual Checklist

Before committing, verify:

### Code Quality
- [ ] No `console.log()` statements (use proper logger)
- [ ] No commented-out code (remove if not needed)
- [ ] No debug code left in production paths
- [ ] No `TODO` or `FIXME` comments for critical issues

### Security
- [ ] No hardcoded API keys or secrets
- [ ] No passwords in code
- [ ] No database credentials in files
- [ ] Environment variables used for all sensitive data
- [ ] `.env` files NOT staged for commit
- [ ] No private keys (`.pem`, `.key`, `.p12`) in code

### Files
- [ ] No `node_modules/` directories staged
- [ ] No build artifacts (`dist/`, `build/`) staged
- [ ] No database files (`.db`, `.sqlite`) staged
- [ ] No log files (`.log`) staged
- [ ] No large files (>10MB) staged
- [ ] `.gitignore` is up to date

### Dependencies
- [ ] No new dependencies with known vulnerabilities
- [ ] `package-lock.json` updated and committed
- [ ] New dependencies reviewed for trustworthiness
- [ ] License compatibility checked

### Documentation
- [ ] README updated if needed
- [ ] API documentation updated if endpoints changed
- [ ] CHANGELOG updated with changes
- [ ] Comments added for complex code

---

## 🚀 Quick Commands Reference

### Run All Security Checks
```powershell
# Comprehensive check (recommended before commit)
npm run security:all

# This runs:
# 1. security-audit.ps1 (secrets, files, etc.)
# 2. npm audit --production (vulnerabilities)
```

### Fix Common Issues

**Fix npm vulnerabilities:**
```powershell
npm audit fix
```

**Remove .env from staging:**
```powershell
git reset HEAD .env
git reset HEAD backend/.env
git reset HEAD cloud-backend/.env
git reset HEAD mobile/.env
```

**Remove database files from git:**
```powershell
git rm --cached *.db
git rm --cached *.sqlite
```

**Remove large files:**
```powershell
git rm --cached path/to/large-file.exe
```

**Update .gitignore:**
```powershell
# After updating .gitignore
git rm -r --cached .
git add .
git commit -m "Update .gitignore"
```

---

## 🔍 Reviewing Staged Files

### Check what's staged:
```powershell
git status
```

### View differences:
```powershell
# See all changes
git diff --cached

# Search for secrets in staged files
git diff --cached | Select-String -Pattern "(api_key|password|secret|token)"
```

### List staged files:
```powershell
git diff --cached --name-only
```

---

## ⚠️ Common Mistakes to Avoid

### ❌ DON'T:
- Commit `.env` files
- Commit `node_modules/` directories
- Commit database files with user data
- Commit build artifacts (`dist/`, `*.exe`)
- Hardcode API keys in code
- Leave debug code in production
- Commit large binary files (>10MB)
- Ignore security audit warnings

### ✅ DO:
- Use `.env.example` templates
- Exclude dependencies via `.gitignore`
- Document configuration requirements
- Use environment variables for secrets
- Run security checks before commit
- Review security audit reports
- Keep `.gitignore` updated
- Sign production builds

---

## 🛡️ Security Best Practices

### Environment Variables
```javascript
// ✅ GOOD - Use environment variables
const apiKey = process.env.VIRUSTOTAL_API_KEY;

// ❌ BAD - Hardcoded secret
const apiKey = "abc123def456";
```

### Secrets Management
```bash
# ✅ GOOD - Template file
# .env.example
VIRUSTOTAL_API_KEY=your_api_key_here

# ❌ BAD - Actual secret in repository
# .env (this file should be in .gitignore!)
VIRUSTOTAL_API_KEY=abc123realkey456
```

### Database Handling
```javascript
// ✅ GOOD - Gitignored database
const dbPath = process.env.DATABASE_PATH || './data/nebula-shield.db';

// ❌ BAD - Committed database with user data
// Committing .db files exposes user information!
```

---

## 📊 Interpreting Security Audit Results

### NPM Audit Output

**Severity Levels:**
- **Critical** 🔴 - Fix immediately (remote code execution, auth bypass)
- **High** 🟠 - Fix soon (SQL injection, XSS, data exposure)
- **Moderate** 🟡 - Review and fix (CORS issues, weak validation)
- **Low** 🟢 - Monitor (information disclosure)

**Example:**
```
found 0 vulnerabilities in 1234 scanned packages
✅ Safe to commit
```

```
found 2 high severity vulnerabilities
❌ Run: npm audit fix
```

### Security Audit Script Output

**Green (✅):** All checks passed
**Yellow (⚠️):** Warnings - review before commit
**Red (❌):** Errors - fix before commit

---

## 🎯 Pre-Commit Workflow

### Recommended workflow before every commit:

```powershell
# 1. Run security check
npm run security:check

# 2. Check git status
git status

# 3. Review staged changes
git diff --cached

# 4. Search for secrets
git diff --cached | Select-String -Pattern "(api_key|password|secret)"

# 5. If all clear, commit
git commit -m "Your commit message"

# 6. Push to GitHub
git push
```

---

## 🔄 Automated Pre-Commit Hooks

### Option 1: Manual Script (Current)
Run `npm run security:check` before each commit.

### Option 2: Husky (Future Enhancement)
Automatically runs checks on `git commit`:

```bash
# Install Husky
npm install --save-dev husky

# Add pre-commit hook
npx husky add .husky/pre-commit "npm run security:check"
```

---

## 📞 Troubleshooting

### Security check fails with false positive
**Solution:** Review the specific warning and add exception if needed.

### npm audit shows vulnerabilities in devDependencies
**Solution:** Only production dependencies matter. Run:
```powershell
npm audit --production
```

### Large files detected but needed
**Solution:** 
1. Check if file is truly necessary
2. Use Git LFS for large binaries
3. Host files externally (CDN)

### .env accidentally committed
**Solution:**
```powershell
# Remove from repository history
git rm --cached .env

# Invalidate exposed secrets
# - Rotate API keys
# - Change passwords
# - Regenerate JWT secret

# Commit the removal
git commit -m "Remove .env from repository"
```

---

## 📚 Additional Resources

- [SECURITY.md](./SECURITY.md) - Full security policy
- [GITHUB_SECURITY_GUIDE.md](./GITHUB_SECURITY_GUIDE.md) - GitHub optimization
- [.gitignore](./.gitignore) - Excluded files reference
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Development guidelines

---

**Remember:** Security is everyone's responsibility. When in doubt, run the security check!

```powershell
npm run security:check
```

✅ **Commit confidently, knowing your code is secure.**
