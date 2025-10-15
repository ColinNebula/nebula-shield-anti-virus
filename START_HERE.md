# 🚀 Nebula Shield - Quick Start Guide

## Starting Nebula Shield

### Windows (PowerShell)

**Option 1: Easy Start (Recommended)**
```powershell
.\start-nebula-shield.ps1
```

**Option 2: Manual Start**
```powershell
# Terminal 1 - Backend Scanner
cd backend\build\bin\Release
.\nebula_shield_backend.exe

# Terminal 2 - Auth Server  
cd backend
node auth-server.js

# Terminal 3 - React Frontend
npm start
```

---

## Stopping Nebula Shield

```powershell
.\stop-nebula-shield.ps1
```

Or press `Ctrl+C` in each terminal window.

---

## Accessing the Application

- **Frontend**: http://localhost:3000
- **Auth Server**: http://localhost:8081
- **Backend API**: http://localhost:8080

---

## Login Credentials

```
Email:    colinnebula@gmail.com
Password: Nebula2025!
```

---

## Payment System

### Demo Mode (No Configuration Needed)
- Go to Premium page
- Click "Quick Upgrade (Demo)"
- Instant premium access!

### Real Payments (Requires Configuration)
1. **Stripe**: Add keys to `backend/.env`
2. **PayPal**: Add credentials to `backend/.env`
3. **Email**: Configure in `backend/.env`

See `PAYMENT-SETUP-GUIDE.md` for details.

---

## Troubleshooting

### Services Won't Start
```powershell
# Check if ports are in use
netstat -ano | findstr "3000 8080 8081"

# Kill processes on specific ports
Stop-Process -Id <PID> -Force
```

### Backend Not Found
```powershell
# Rebuild the C++ backend
cd backend\build
cmake --build . --config Release
```

### Auth Server Errors
```powershell
# Reinstall dependencies
cd backend
npm install
```

### React Won't Start
```powershell
# Reinstall dependencies
npm install

# Clear cache
npm cache clean --force
rm -r node_modules package-lock.json
npm install
```

---

## Documentation

- `PAYMENT-SETUP-GUIDE.md` - Payment system configuration
- `PAYMENT-SYSTEM-SUMMARY.md` - Payment features overview
- `README.md` - General project information

---

## Need Help?

Check the terminal windows for error messages and status information.
