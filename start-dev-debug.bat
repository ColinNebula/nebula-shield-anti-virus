@echo off
echo ========================================
echo Nebula Shield - Development Server
echo WebSocket Debug Mode
echo ========================================
echo.

REM Kill any existing servers
echo Cleaning up existing processes...
taskkill /F /IM node.exe >nul 2>&1
timeout /t 2 >nul

REM Clear terminal
cls

echo ========================================
echo Starting Backend Server (Port 8080)
echo ========================================
start "Nebula Backend" cmd /k "cd backend && set NODE_ENV=development && node auth-server.js"

REM Wait for backend to start
timeout /t 3

echo.
echo ========================================
echo Starting Frontend Server (Port 3002)
echo ========================================
echo WebSocket HMR should connect on ws://127.0.0.1:3002
echo.
start "Nebula Frontend" cmd /k "npm run dev"

echo.
echo ========================================
echo Servers Starting...
echo ========================================
echo.
echo Backend:  http://localhost:8080
echo Frontend: http://localhost:3002
echo.
echo If WebSocket errors occur:
echo 1. Check Windows Firewall
echo 2. Disable antivirus temporarily
echo 3. Use 127.0.0.1 instead of localhost
echo.
echo Press any key to open browser...
pause >nul

start http://127.0.0.1:3002/dashboard

echo.
echo Servers are running in separate windows.
echo Close those windows to stop the servers.
echo.
pause
