# 🔌 WebSocket Error Fix Guide

**Error**: `WebSocket error: Event {isTrusted: true, type: 'error'...}`

---

## 🎯 What This Error Means

The WebSocket error in `installHook.js` indicates that **Vite's Hot Module Replacement (HMR)** cannot establish a WebSocket connection for live reloading. This is NOT a critical application error - your app will still work, but **hot reloading won't function**.

---

## ✅ Solutions Applied

### 1. **Vite Configuration Updated**
- ✅ Explicit IPv4 binding (`127.0.0.1` instead of `localhost`)
- ✅ HMR WebSocket configuration added
- ✅ Proper port settings for WebSocket client
- ✅ CORS enabled for development

### 2. **Tools Created**
- ✅ `start-dev-debug.bat` - Debug mode development server
- ✅ `public/websocket-test.html` - WebSocket diagnostic tool

---

## 🚀 How to Fix (Step by Step)

### Option 1: Use the Debug Startup Script (Recommended)

```bash
# Just double-click this file:
start-dev-debug.bat
```

This will:
- Clean up existing servers
- Start backend on port 8080
- Start frontend on port 3002
- Open browser to the correct URL

### Option 2: Manual Restart

```bash
# Stop all servers
Get-Process | Where-Object {$_.ProcessName -match "node"} | Stop-Process -Force

# Start backend
cd backend
npm start

# In new terminal - Start frontend
npm run dev
```

### Option 3: Use npm scripts

```bash
# This runs both servers concurrently
npm run dev:all
```

---

## 🧪 Test WebSocket Connection

1. **Start your servers** (using any method above)

2. **Open the diagnostic page**:
   ```
   http://127.0.0.1:3002/websocket-test.html
   ```

3. **Check the test results**:
   - ✅ Green = WebSocket working
   - ❌ Red = WebSocket failed

---

## 🔧 Common Causes & Fixes

### 1. Server Not Running
**Symptom**: WebSocket immediately fails
**Fix**: Ensure dev server is running on port 3002
```bash
npm run dev
```

### 2. IPv6 vs IPv4 Issue
**Symptom**: WebSocket fails even when server is running
**Fix**: Use `127.0.0.1` instead of `localhost`
```
http://127.0.0.1:3002/dashboard  ✅
http://localhost:3002/dashboard  ❌ (might fail)
```

### 3. Windows Firewall Blocking
**Symptom**: WebSocket connection timeout
**Fix**: 
```powershell
# Add firewall rule
New-NetFirewallRule -DisplayName "Vite Dev Server" -Direction Inbound -LocalPort 3002 -Protocol TCP -Action Allow
```

### 4. Antivirus Blocking WebSockets
**Symptom**: Intermittent WebSocket failures
**Fix**: Temporarily disable antivirus or add exception for Node.js

### 5. Port Already in Use
**Symptom**: Server won't start or WebSocket fails
**Fix**:
```powershell
# Find process using port 3002
Get-NetTCPConnection -LocalPort 3002 | Select-Object OwningProcess

# Kill the process
Stop-Process -Id <ProcessID> -Force
```

### 6. Browser Cache Issues
**Symptom**: WebSocket error persists after fixes
**Fix**: Hard refresh browser
- **Windows**: `Ctrl + Shift + R`
- **Mac**: `Cmd + Shift + R`
- Or: DevTools → Right-click Refresh → "Empty Cache and Hard Reload"

---

## 🛡️ For Nebula Shield Specifically

Since this is an antivirus application, it might be **blocking its own WebSocket connections**!

**Temporary Fix**:
1. Open Nebula Shield dashboard
2. Go to **Firewall Settings**
3. Add exception for:
   - `http://127.0.0.1:3002`
   - `ws://127.0.0.1:3002`
   - Port: `3002` (TCP/WebSocket)

**Or disable real-time protection during development**:
```javascript
// In your dev environment
localStorage.setItem('dev_mode', 'true');
```

---

## 📊 Verify It's Working

### 1. Check Terminal Output
When you run `npm run dev`, you should see:
```
  VITE v7.1.12  ready in XXX ms

  ➜  Local:   http://127.0.0.1:3002/
  ➜  Network: use --host to expose
  ➜  press h + enter to show help
```

### 2. Check Browser Console
- ✅ **No WebSocket errors** = Working perfectly
- ⚠️ **WebSocket error but app works** = HMR disabled, manual refresh needed
- ❌ **App won't load** = Server not running

### 3. Test Hot Reload
1. Open `http://127.0.0.1:3002/dashboard`
2. Edit a React component (e.g., change some text)
3. Save the file
4. **If HMR works**: Changes appear instantly
5. **If HMR broken**: Must manually refresh browser

---

## 🎯 Quick Checklist

- [ ] Backend running on port 8080
- [ ] Frontend running on port 3002
- [ ] Using `127.0.0.1` (not `localhost`)
- [ ] Firewall allows port 3002
- [ ] No other process using port 3002
- [ ] Browser cache cleared
- [ ] Antivirus not blocking WebSocket

---

## 🚨 If Nothing Works

### Nuclear Option: Complete Reset

```powershell
# 1. Kill all Node processes
Get-Process node -ErrorAction SilentlyContinue | Stop-Process -Force

# 2. Clear all caches
Remove-Item -Recurse -Force node_modules
Remove-Item -Recurse -Force backend/node_modules
Remove-Item -Recurse -Force .vite
Remove-Item -Force package-lock.json
Remove-Item -Force backend/package-lock.json

# 3. Reinstall
npm install
cd backend
npm install
cd ..

# 4. Start fresh
npm run dev:all
```

### Last Resort: Use Production Build
If HMR WebSocket keeps failing, you can build and run production mode:
```bash
npm run build
npm run preview
```
This doesn't use WebSockets (no hot reload), but the app will work perfectly.

---

## 💡 Understanding the Error

**Why is it in `installHook.js`?**
- This is Vite's HMR (Hot Module Replacement) client
- It tries to connect to `ws://127.0.0.1:3002` for live updates
- If connection fails, you'll see the WebSocket error

**Is it critical?**
- ❌ No! Your app will still work
- ✅ You just won't get instant hot reloading
- ✅ You'll need to manually refresh after code changes

**Why does it happen?**
1. Server not ready when page loads
2. IPv6/IPv4 address mismatch
3. Firewall/antivirus blocking
4. Port conflicts
5. Network configuration issues

---

## 📞 Still Having Issues?

Check the diagnostic page:
```
http://127.0.0.1:3002/websocket-test.html
```

This will show you exactly what's failing and why.

---

**Created for Nebula Shield Anti-Virus**  
**Updated**: November 3, 2025
