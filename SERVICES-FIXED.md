# ✅ BACKEND SERVICES FIXED!

## Problem Resolved

The auth server (port 8082) and backend server (port 8080) were not running, causing connection errors.

---

## ✅ Current Status

Your services are now running:

- ✅ **Auth Server** - Running on port **8082**
- ✅ **Backend Server** - Running on port **8080**
- ✅ **Frontend** - Running on port **3001**

**Access Nebula Shield at:** http://localhost:3001

---

## 🚀 How to Start Services

### Option 1: Automatic Startup (Easiest)

Double-click this file:
```
START-ALL-SERVICES.bat
```

This will:
1. Start Auth Server (port 8082)
2. Start Backend Server (port 8080)
3. Start Frontend (port 3001)
4. Open your browser to http://localhost:3001

### Option 2: Manual Startup

**Terminal 1 - Auth Server:**
```powershell
cd backend
node auth-server.js
```

**Terminal 2 - Backend Server:**
```powershell
node mock-backend.js
```

**Terminal 3 - Frontend:**
```powershell
npm start
```

---

## 🔍 Check Service Status

### PowerShell Command:
```powershell
.\Check-Services.ps1
```

### Manual Check:
```powershell
# Check what's listening on our ports
netstat -ano | findstr ":8080 :8082 :3001"
```

### Quick Test:
```powershell
# Test backend
Invoke-RestMethod -Uri "http://localhost:8080/api/status"

# Test auth server (should respond)
Invoke-WebRequest -Uri "http://localhost:8082"

# Test frontend (should open in browser)
start http://localhost:3001
```

---

## 🔐 Login Credentials

After starting all services, login with:

```
Email:    admin@nebulashield.local
Password: NebulaAdmin2025!
```

**Or use existing account:**
```
Email:    colinnebula@nebula3ddev.com
Password: Nebula2025!
```

---

## 📋 Common Issues & Solutions

### Issue: "Cannot connect to server on port 8082"

**Cause:** Auth server not running

**Solution:**
```powershell
cd backend
node auth-server.js
```

### Issue: "Cannot connect to server on port 8080"

**Cause:** Backend server not running

**Solution:**
```powershell
node mock-backend.js
```

### Issue: "Port already in use"

**Cause:** Service is already running or another app is using the port

**Solution:**
```powershell
# Find what's using the port
netstat -ano | findstr :8080

# Kill the process (replace PID with actual process ID)
taskkill /PID <pid> /F

# Then restart the service
```

### Issue: Frontend won't load

**Cause:** Frontend not started

**Solution:**
```powershell
npm start
```

---

## 🛠️ Service Management

### Start All Services:
```batch
START-ALL-SERVICES.bat
```

### Stop All Services:
Find the PowerShell windows titled:
- "Nebula Shield - Auth Server"
- "Nebula Shield - Backend"  
- "Nebula Shield - Frontend"

Close each window or press `Ctrl+C` in each terminal.

### Restart a Service:
1. Close the service's terminal window
2. Start it again using the manual startup commands above

---

## 📊 Service Details

### Auth Server (Port 8082)
- **File:** `backend/auth-server.js`
- **Purpose:** User authentication, JWT tokens, user management
- **Endpoints:** `/api/auth/*`, `/api/admin/*`
- **Database:** `data/auth.db`

### Backend Server (Port 8080)
- **File:** `mock-backend.js`
- **Purpose:** Core antivirus functionality, scanning, quarantine
- **Endpoints:** `/api/status`, `/api/scan/*`, `/api/quarantine`, `/api/settings`
- **Database:** `backend/data/quarantine.db`

### Frontend (Port 3001)
- **File:** React application (`src/`)
- **Purpose:** User interface
- **Access:** http://localhost:3001

---

## 🎯 Quick Start Workflow

1. **Start Services:**
   ```
   Double-click START-ALL-SERVICES.bat
   ```

2. **Wait for Services:**
   - 3 terminal windows will open
   - Wait ~10 seconds for all to initialize
   - Browser opens automatically

3. **Login:**
   - URL: http://localhost:3001
   - Email: `admin@nebulashield.local`
   - Password: `NebulaAdmin2025!`

4. **Change Password:**
   - Go to Settings → Account
   - Change default password
   - Save changes

5. **Start Using:**
   - Run a quick scan
   - Configure VirusTotal API (optional)
   - Explore features

---

## ⚙️ Configuration Files

### Environment Variables:

**.env** (root directory):
```env
REACT_APP_VIRUSTOTAL_API_KEY=your_api_key_here
REACT_APP_API_URL=http://localhost:8080
REACT_APP_AUTH_URL=http://localhost:8082
```

**backend/.env**:
```env
AUTH_PORT=8082
JWT_SECRET=nebula-shield-secret-key
```

---

## 🔄 Development vs Production

### Development Mode (Current):
- Frontend runs on port 3001
- Hot reload enabled
- Debug logging
- Uses mock data

### Production Mode:
```powershell
# Build production frontend
npm run build

# Serve production build
# (Configure web server like nginx or IIS)
```

---

## 📞 Need Help?

### Check Service Logs:

Each terminal window shows real-time logs. Look for:
- ✅ Green messages = Success
- ⚠️ Yellow messages = Warnings
- ❌ Red messages = Errors

### Common Startup Messages:

**Auth Server:**
```
🔐 Nebula Shield Auth Server
📡 Listening on port 8082
✅ Auth database connected
✅ Users table ready
```

**Backend:**
```
🛡️ Nebula Shield Anti-Virus Mock Backend running on http://localhost:8080
✅ Backend ready for frontend connection!
```

**Frontend:**
```
Compiled successfully!
webpack compiled with 0 errors
```

---

## 📦 Files Created

Helper scripts created for you:

1. ✅ `START-ALL-SERVICES.bat` - Start all services automatically
2. ✅ `Check-Services.ps1` - Check service status
3. ✅ `SERVICES-FIXED.md` - This documentation

---

## ✅ Summary

**Problem:** Backend services weren't running  
**Solution:** Started auth server (8082) and backend (8080)  
**Status:** All services running  
**Access:** http://localhost:3001  
**Login:** admin@nebulashield.local / NebulaAdmin2025!

---

**Built with ❤️ by Colin Nebula for Nebula3ddev.com**

*Stay Protected. Stay Secure.* 🛡️

---

**Last Updated:** October 13, 2025  
**All Services:** ✅ RUNNING
