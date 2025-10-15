# Registration Failed - Troubleshooting Guide

## Problem
Getting "Registration Failed" error when trying to register a new account.

## Root Cause
The **Auth Server** (NebulaShieldAuth) service is not running. This service handles:
- User registration
- User login
- JWT token generation
- Settings persistence

Without it running, the frontend can't communicate with the authentication backend.

## Quick Fix

### Option 1: Start Services (Recommended)
Run as **Administrator**:
```powershell
cd "C:\Program Files\Nebula Shield"
.\nssm.exe start NebulaShieldAuth
.\nssm.exe start NebulaShieldBackend
```

### Option 2: Use Services Manager
1. Press `Win + R`
2. Type `services.msc` and press Enter
3. Find "Nebula Shield Auth Server"
4. Right-click → **Start**
5. Find "Nebula Shield Antivirus Backend"  
6. Right-click → **Start**

### Option 3: Run Diagnostic Script
```powershell
cd Z:\Directory\projects\nebula-shield-anti-virus\installer
.\diagnose-services.ps1
```
Then select option **[2] Start all services**

## Verify Fix

### Check Services Are Running
```powershell
Get-Service | Where-Object {$_.Name -like "NebulaShield*"}
```

You should see:
```
Status   Name                    DisplayName
------   ----                    -----------
Running  NebulaShieldAuth        Nebula Shield Auth Server
Running  NebulaShieldBackend     Nebula Shield Antivirus Backend
Running  NebulaShieldFrontend    Nebula Shield Frontend Server
```

### Test Auth Server
Open PowerShell and test:
```powershell
curl http://localhost:8081/api/health
```

Should return:
```json
{"status":"ok","timestamp":"..."}
```

### Try Registration Again
1. Open http://localhost:3000
2. Click "Register"
3. Fill in the form:
   - Username
   - Email
   - Password
4. Click "Create Account"
5. Should successfully register and redirect to login

## Why Services Stopped

Services may stop due to:
1. **Manual stop** - Someone stopped them via services.msc
2. **Error/crash** - Service encountered an error
3. **Port conflict** - Another app using port 8081
4. **Startup type** - Not set to "Automatic"

## Make Services Auto-Start

To ensure services start automatically on boot:

```powershell
# Run as Administrator
cd "C:\Program Files\Nebula Shield"

# Set to auto-start
.\nssm.exe set NebulaShieldBackend Start SERVICE_AUTO_START
.\nssm.exe set NebulaShieldAuth Start SERVICE_AUTO_START
.\nssm.exe set NebulaShieldFrontend Start SERVICE_AUTO_START

# Start now
.\nssm.exe start NebulaShieldBackend
.\nssm.exe start NebulaShieldAuth
.\nssm.exe start NebulaShieldFrontend
```

## Common Errors

### "Connection refused"
**Cause**: Auth server not running  
**Fix**: Start NebulaShieldAuth service

### "Network error"
**Cause**: Firewall blocking localhost  
**Fix**: Add exception for localhost or disable firewall temporarily

### "Port 8081 already in use"
**Cause**: Another app using the port  
**Fix**: Find and stop the conflicting app:
```powershell
netstat -ano | findstr :8081
# Note the PID, then:
Stop-Process -Id <PID>
```

### "Service won't start"
**Cause**: Missing dependencies or configuration  
**Fix**: Check logs at:
```
C:\Program Files\Nebula Shield\data\logs\auth-error.log
```

## Full Service Restart

If issues persist, restart all services:

```powershell
# Run as Administrator
cd "C:\Program Files\Nebula Shield"

# Stop all
.\nssm.exe stop NebulaShieldBackend
.\nssm.exe stop NebulaShieldAuth
.\nssm.exe stop NebulaShieldFrontend

# Wait 3 seconds
Start-Sleep -Seconds 3

# Start all
.\nssm.exe start NebulaShieldBackend
.\nssm.exe start NebulaShieldAuth
.\nssm.exe start NebulaShieldFrontend
```

## Check Logs

If registration still fails, check logs:

**Auth Server Log:**
```batch
type "C:\Program Files\Nebula Shield\data\logs\auth-service.log"
```

**Auth Server Errors:**
```batch
type "C:\Program Files\Nebula Shield\data\logs\auth-error.log"
```

Look for:
- Database connection errors
- Port binding errors
- Dependency errors

## Database Issues

If the auth database is corrupted:

```powershell
cd "C:\Program Files\Nebula Shield\data"

# Backup old database
Move-Item auth.db auth.db.backup

# Restart auth service (will create new database)
cd "C:\Program Files\Nebula Shield"
.\nssm.exe restart NebulaShieldAuth
```

**Note**: This will delete all users and settings!

## Test Registration

After starting services, test with:

**Username**: testuser  
**Email**: test@example.com  
**Password**: TestPass123!

If successful, you should:
1. See "Registration successful!" message
2. Be redirected to login page
3. Be able to login with the credentials

## Still Not Working?

1. **Reboot computer** - Fresh start often helps
2. **Reinstall services**:
   ```batch
   cd "C:\Program Files\Nebula Shield"
   .\uninstall-services.bat
   .\install-services.bat
   ```
3. **Check Node.js is installed**:
   ```powershell
   node --version
   ```
4. **Run diagnostic script**:
   ```powershell
   cd Z:\Directory\projects\nebula-shield-anti-virus\installer
   .\diagnose-services.ps1
   ```

## Prevention

To avoid this issue in the future:
1. ✅ Set services to auto-start (done during installation)
2. ✅ Don't manually stop services unless needed
3. ✅ Check service status if app doesn't work: `services.msc`
4. ✅ Monitor logs for errors regularly

---

**Quick Command Reference:**
```powershell
# Check status
Get-Service NebulaShield*

# Start services
nssm start NebulaShieldAuth
nssm start NebulaShieldBackend

# Test endpoints
curl http://localhost:8081/api/health  # Auth
curl http://localhost:8080/api/status  # Backend
curl http://localhost:3000             # Frontend
```

**Solution Applied**: Services have been started. You can now register successfully!
