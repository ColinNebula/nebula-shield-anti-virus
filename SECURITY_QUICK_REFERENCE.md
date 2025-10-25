# 🔒 Security Quick Reference

## Before Every Commit

```powershell
npm run security:check
```

## Common Commands

| Command | Purpose |
|---------|---------|
| `npm run security:check` | Full security audit (recommended) |
| `npm run security:audit:production` | Check production dependencies |
| `npm run integrity:verify` | Verify file integrity |
| `npm run security:all` | Complete security scan |
| `npm audit fix` | Fix vulnerabilities automatically |

## What Gets Excluded from Git

✅ **Automatically excluded via `.gitignore`:**
- `node_modules/` (1.5 GB)
- `.env` files (all secrets)
- `*.db` (databases)
- `dist/`, `build/` (build outputs)
- `*.exe`, `*.dmg`, `*.apk`, `*.ipa` (binaries)
- `*.log` (logs)
- `*.pem`, `*.key` (certificates)

## Emergency Fixes

### Accidentally staged .env file:
```powershell
git reset HEAD .env
```

### Committed secret by mistake:
```powershell
git rm --cached .env
# Then rotate the exposed secret!
```

### Fix npm vulnerabilities:
```powershell
npm audit fix
```

## File Locations

- **Security Policy:** `SECURITY.md`
- **GitHub Guide:** `GITHUB_SECURITY_GUIDE.md`
- **Pre-Commit Checklist:** `PRE_COMMIT_CHECKLIST.md`
- **Security Audit Script:** `security-audit.ps1`
- **Environment Templates:** `.env.example` (and in subdirectories)

## Environment Setup

```powershell
# After cloning repository
cp .env.example .env
cp backend/.env.example backend/.env
cp cloud-backend/.env.example cloud-backend/.env
cp mobile/.env.example mobile/.env

# Then edit .env files with your secrets
```

## Repository Size

- **On GitHub:** ~50-100 MB ✅
- **With dependencies:** ~3,300 MB (local only)
- **Excluded:** ~1,800+ MB

## Security Status

✅ Secrets protected
✅ Dependencies audited
✅ Code integrity verified
✅ Build artifacts excluded
✅ GitHub-ready

## Need Help?

- Security issues: See `SECURITY.md`
- Setup questions: See `GITHUB_SECURITY_GUIDE.md`
- Commit workflow: See `PRE_COMMIT_CHECKLIST.md`

---

**Pro Tip:** Add to git pre-commit hook:
```bash
npm run security:check || exit 1
```
