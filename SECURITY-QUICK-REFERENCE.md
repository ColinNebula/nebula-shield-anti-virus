# Security Quick Reference Card

## 🚨 Before Committing Code

```bash
# Run security audit
npm audit

# Verify file integrity
node src/utils/integrityChecker.js verify

# Check for secrets in code
git diff | grep -iE '(password|secret|token|key|api.key)'
```

## 🔐 Environment Variables (Production)

```bash
# REQUIRED - Set these before starting production server
JWT_SECRET=<generate-32+-char-random-string>
BCRYPT_ROUNDS=12
JWT_EXPIRES_IN=24h
NODE_ENV=production
CORS_ORIGINS=https://yourdomain.com

# Generate strong secret (PowerShell):
-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 48 | % {[char]$_})

# Generate strong secret (Bash/Linux):
openssl rand -base64 48
```

## 🛡️ Electron Security Checklist

- [x] contextIsolation: true
- [x] sandbox: true
- [x] nodeIntegration: false
- [x] DevTools disabled in production
- [x] IPC handlers validate sender
- [x] URLs validated before openExternal
- [x] CSP enforced in index.html

## 🔒 Backend Security Checklist

- [x] Helmet headers enabled
- [x] Rate limiting on /api/auth
- [x] Body size limits (10KB)
- [x] bcrypt rounds ≥ 12
- [x] JWT secret ≥ 32 chars
- [x] Token expiry ≤ 24h
- [x] Input validation on all endpoints

## 🚀 Production Deployment

```bash
# 1. Set environment variables
export JWT_SECRET="your-very-strong-secret"
export NODE_ENV="production"

# 2. Verify integrity
node src/utils/integrityChecker.js verify

# 3. Run security audit
npm audit --audit-level=moderate

# 4. Build production app
npm run build
npm run electron:build:win

# 5. Sign executable (Windows)
signtool sign /f cert.pfx /p password /t http://timestamp.digicert.com dist/*.exe

# 6. Generate checksums
certutil -hashfile "dist/Nebula Shield Anti-Virus Setup 0.1.0.exe" SHA256
```

## 🔍 Security Testing

```bash
# Test auth endpoints
curl -X POST http://localhost:8082/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"wrong"}'

# Test rate limiting (run 100+ times)
for i in {1..110}; do curl http://localhost:8082/api/auth/login; done

# Verify CSP headers
curl -I http://localhost:3002

# Check open ports
netstat -ano | findstr "8082"
```

## 🐛 Common Security Issues

### Issue: Weak JWT Secret
```bash
# BAD - Never use default secrets
JWT_SECRET="nebula-shield-secret-key-change-in-production"

# GOOD - Generate strong random secret
JWT_SECRET=$(openssl rand -base64 48)
```

### Issue: Node Integration Enabled
```javascript
// BAD - Allows require() in renderer
webPreferences: {
  nodeIntegration: true,
  contextIsolation: false
}

// GOOD - Secure configuration
webPreferences: {
  nodeIntegration: false,
  contextIsolation: true,
  sandbox: true,
  preload: 'path/to/secure-preload.js'
}
```

### Issue: Unvalidated IPC
```javascript
// BAD - No validation
ipcMain.handle('open-url', (event, url) => {
  shell.openExternal(url); // Any URL!
});

// GOOD - Whitelist validation
ipcMain.handle('open-url', (event, url) => {
  const allowedHosts = ['github.com', 'trusted.com'];
  const parsed = new URL(url);
  if (!allowedHosts.includes(parsed.hostname)) {
    return { error: 'Untrusted domain' };
  }
  shell.openExternal(url);
});
```

## 📞 Security Contacts

- **Report Security Issue:** security@nebulashield.com
- **PGP Key:** https://nebulashield.com/security.asc
- **Security Policy:** See SECURITY-HARDENING.md

## 🔄 Update Frequency

- **Dependencies:** Monthly (`npm update`)
- **Security Patches:** Immediately
- **Major Versions:** Quarterly (with testing)

---

**Last Updated:** October 22, 2025  
**Version:** 1.0
