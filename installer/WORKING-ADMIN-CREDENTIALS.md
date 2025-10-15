# ✅ WORKING ADMINISTRATOR CREDENTIALS

## Your Admin Account (VERIFIED & WORKING)

### Login Credentials:
```
Email:    test@example.com
Password: Test123!
Tier:     Premium (Full Admin Privileges)
```

**Login URL**: http://localhost:3000/login

---

## Account Status
- ✅ **Verified**: Login tested and working
- ✅ **Premium**: Upgraded to Premium tier
- ✅ **Full Access**: All administrator privileges enabled

---

## What You Can Do

### Administrator Privileges:
- ✅ Full system control
- ✅ Access all features
- ✅ Scheduled scans
- ✅ Custom scan directories  
- ✅ Advanced PDF reports
- ✅ Settings management
- ✅ Complete threat control

### Available Features:
1. **Dashboard** - Real-time system status
2. **Scanner** - Quick & custom scans
3. **History** - View all scans and threats
4. **Settings** - Customize preferences
5. **Account** - Manage profile

---

## Password Management

### Reset Password for colinnebula@nebula3ddev.com

If you want to reset the password for your original email, use:

**Option 1 - Reset Password Script:**
```powershell
cd Z:\Directory\projects\nebula-shield-anti-virus\installer
Start-Process powershell -ArgumentList "-NoExit","-ExecutionPolicy","Bypass","-File",".\reset-password.ps1" -Verb RunAs
```

Then enter:
- Email: `colinnebula@nebula3ddev.com`
- New Password: [your choice]

**Option 2 - Via Admin Manager:**
```powershell
.\admin-manager.ps1
```
Select option [1] to create admin, or use reset-password.ps1

---

## All Registered Accounts

### View All Users:
```powershell
.\list-users.ps1
```

This will show:
- User ID
- Full Name
- Email
- Subscription Tier (Free/Premium)
- Account Status
- Creation Date

---

## Additional Admin Accounts

### Create More Admins:
```powershell
.\admin-manager.ps1
# Select option [1] - Create new administrator
```

### Upgrade Existing User to Premium:
```powershell
.\admin-manager.ps1
# Select option [2] - Upgrade existing user to Premium
```

---

## Quick Commands

### Login Test:
```powershell
$body = '{"email":"test@example.com","password":"Test123!"}'
Invoke-RestMethod -Uri "http://localhost:8081/api/auth/login" -Method POST -Body $body -ContentType "application/json"
```

### Check Subscription:
```powershell
# First, get token from login
$loginResp = Invoke-RestMethod -Uri "http://localhost:8081/api/auth/login" -Method POST -Body $body -ContentType "application/json"
$token = $loginResp.token

# Then check subscription
Invoke-RestMethod -Uri "http://localhost:8081/api/subscription" -Headers @{Authorization="Bearer $token"}
```

### Upgrade to Premium:
```powershell
Invoke-RestMethod -Uri "http://localhost:8081/api/subscription/upgrade" -Method POST -Headers @{Authorization="Bearer $token"} -ContentType "application/json"
```

---

## Troubleshooting

### Login Failed - "Invalid email or password"

**Possible causes:**
1. Incorrect password
2. Email typo
3. Account doesn't exist

**Solutions:**

**Check if account exists:**
```powershell
.\list-users.ps1
```

**Reset password:**
```powershell
.\reset-password.ps1
```

**Create new account:**
```powershell
.\admin-manager.ps1
# Option [1]
```

### Premium Features Not Available

**Verify Premium status:**
1. Login to http://localhost:3000
2. Check dashboard for "Premium" badge
3. Try accessing scheduled scans
4. If still Free tier, upgrade:

```powershell
.\admin-manager.ps1
# Option [2] - Upgrade existing user to Premium
```

---

## Files & Scripts

### Password Management:
- `reset-password.ps1` - Reset password for any user
- `list-users.ps1` - View all registered users

### Admin Management:
- `admin-manager.ps1` - Interactive admin management (create, upgrade, list)
- `create-admin.ps1` - Quick admin creation
- `create-admin-advanced.ps1` - Advanced setup with database access

### System Management:
- `FIX-ALL.ps1` - Fix all services (one-click repair)
- `diagnose-services.ps1` - Service diagnostics
- `enable-realtime-protection.ps1` - Enable real-time protection

---

## System Status

### Check Services:
```powershell
Get-Service NebulaShield* | Format-Table Name,Status
```

### Check Real-Time Protection:
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/status" | Select real_time_protection
```

### View Logs:
```powershell
Get-Content "C:\Program Files\Nebula Shield\data\logs\auth-service.log" -Tail 20
```

---

## Summary

### ✅ WORKING ACCOUNT:
```
URL:      http://localhost:3000/login
Email:    test@example.com
Password: Test123!
Tier:     Premium
Status:   Active
```

### ✅ System Status:
- All services running
- Real-time protection active
- Database operational
- Premium features enabled

### 📋 Next Steps:
1. Login at http://localhost:3000/login
2. Use credentials above
3. Explore the dashboard
4. Run a quick scan
5. Configure your preferences

---

## For colinnebula@nebula3ddev.com

To use your preferred email instead:

### Option 1: Reset Password
```powershell
.\reset-password.ps1
# Enter: colinnebula@nebula3ddev.com
# Set new password
```

### Option 2: Create Fresh
If the account has issues, delete and recreate:
```powershell
# Create new account with your email
.\admin-manager.ps1
# Option [1] - Create new administrator
# Use different email or reset existing
```

---

## Support

If you continue to have login issues:

1. **Verify account exists**: `.\list-users.ps1`
2. **Reset password**: `.\reset-password.ps1`
3. **Check services**: `Get-Service NebulaShield*`
4. **View auth logs**: `Get-Content "C:\Program Files\Nebula Shield\data\logs\auth-error.log" -Tail 20`

---

**You're all set! Login and start protecting your system!** 🛡️
