# Deployment & Installation Guide

## Building the Application

### Prerequisites
- Node.js installed on build machine
- PowerShell (Windows)
- All dependencies installed

### Build Steps

1. **Install Dependencies**
   ```bash
   npm install
   cd backend && npm install --production && cd ..
   ```

2. **Check Servers** (if building with server check)
   ```bash
   npm run check:servers
   ```

3. **Build for Windows**
   ```bash
   npm run electron:build:win
   ```

   This will:
   - Check if servers are running
   - Run prebuild checks (verify backend dependencies)
   - Build the React app
   - Package the Electron app with backend included

4. **Output Files**
   - Installer: `dist/Nebula Shield Anti-Virus Setup {version}.exe`
   - Portable: `dist/Nebula Shield Anti-Virus {version}.exe`

## Installation on Other Computers

### System Requirements
- Windows 10/11 (64-bit)
- 4GB RAM minimum
- 500MB free disk space
- Node.js **NOT required** (bundled with app)

### Installation Process

1. **Run the installer**
   - Double-click `Nebula Shield Anti-Virus Setup.exe`
   - Follow the installation wizard
   - Choose installation directory (default recommended)
   - Complete installation

2. **First Launch**
   - The app will automatically:
     - Start the backend server on port 8080
     - Initialize the database
     - Open the login screen

3. **Default Credentials**
   - Email: `admin@test.com`
   - Password: `admin`
   - **Change these immediately after first login!**

## Troubleshooting

### "Cannot connect to backend" Error

**Symptoms:**
- Login page doesn't load
- "Backend server not responding" message
- Cannot perform any actions

**Solutions:**

1. **Check Firewall**
   ```
   - Windows Firewall may block port 8080
   - Allow "Nebula Shield Anti-Virus" through firewall
   - Or manually allow port 8080
   ```

2. **Check Antivirus**
   ```
   - Some antivirus software blocks the backend
   - Add exception for Nebula Shield installation folder
   - Temporarily disable antivirus to test
   ```

3. **Check Port Availability**
   ```powershell
   netstat -ano | findstr :8080
   ```
   If port 8080 is in use, kill the process or change the port

4. **Run as Administrator**
   - Right-click app icon
   - Select "Run as Administrator"

5. **Check Logs**
   - Location: `%APPDATA%\nebula-shield-anti-virus\electron.log`
   - Look for backend errors
   - Check if backend started successfully

### Backend Not Starting

**Check the log file:**
```
%APPDATA%\nebula-shield-anti-virus\electron.log
```

**Common issues:**

1. **Missing node_modules**
   - Reinstall the application
   - Ensure full installation completed

2. **Database errors**
   - Delete `%APPDATA%\nebula-shield-anti-virus\data\auth.db`
   - Restart the app (will recreate database)

3. **Port conflict**
   - Another service using port 8080
   - Close conflicting application

### Icons Not Showing

1. **Clear icon cache**
   ```powershell
   taskkill /f /im explorer.exe
   del %LocalAppData%\IconCache.db /a
   start explorer.exe
   ```

2. **Reinstall**
   - Uninstall current version
   - Delete installation folder
   - Reinstall

## Backend Server Details

### Automatic Startup
- Backend starts automatically when app launches
- Runs on `localhost:8080`
- Only accessible from local machine
- Stops automatically when app closes

### Manual Backend Control
If needed, backend can be started separately:
```bash
cd "C:\Program Files\Nebula Shield Anti-Virus\resources\backend"
node auth-server.js
```

### Health Check
Test if backend is running:
```powershell
Invoke-WebRequest http://localhost:8080/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "Nebula Shield Auth Server",
  "timestamp": "2025-10-26T...",
  "uptime": 123.45,
  "port": 8080
}
```

## Files Included in Installation

```
Nebula Shield Anti-Virus/
├── Nebula Shield Anti-Virus.exe  # Main application
├── resources/
│   ├── app.asar                  # Frontend code (packed)
│   ├── app.asar.unpacked/        # Unpacked files
│   ├── backend/                  # Backend server
│   │   ├── auth-server.js
│   │   ├── node_modules/         # Backend dependencies
│   │   └── ...
│   └── data/                     # Database files
└── ...
```

## Security Notes

1. **Change Default Password**
   - First thing after installation
   - Use strong password

2. **Firewall**
   - Backend only listens on localhost
   - Not accessible from network
   - Safe to allow in firewall

3. **Updates**
   - Check for updates regularly
   - Reinstall to update

## Uninstallation

1. **Normal Uninstall**
   - Control Panel > Programs > Uninstall
   - Or use installer with uninstall option

2. **Complete Removal**
   ```
   - Uninstall via Control Panel
   - Delete: %APPDATA%\nebula-shield-anti-virus
   - Delete: %LOCALAPPDATA%\nebula-shield-anti-virus
   ```

## Support

If issues persist:
1. Check logs: `%APPDATA%\nebula-shield-anti-virus\electron.log`
2. Try running as Administrator
3. Temporarily disable antivirus/firewall
4. Reinstall the application

## Advanced Configuration

### Change Backend Port
Edit environment variables before app starts (advanced users):
```
set AUTH_PORT=8081
"Nebula Shield Anti-Virus.exe"
```

### Database Location
Default: `%APPDATA%\nebula-shield-anti-virus\data\auth.db`

To use custom location, set environment variable:
```
set DATABASE_PATH=C:\custom\path\auth.db
```
