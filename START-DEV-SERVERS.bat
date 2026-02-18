@echo off
echo ====================================
echo   Nebula Shield - Start Dev Servers
echo ====================================
echo.

echo [1/2] Starting Backend Server...
start "Nebula Backend (Port 8080)" cmd /k "cd /d %~dp0backend && echo Backend Server Starting... && node auth-server.js"
timeout /t 3 /nobreak >nul

echo [2/2] Starting Frontend Server...
start "Nebula Frontend (Port 3002)" cmd /k "cd /d %~dp0 && echo Frontend Server Starting... && npm run dev"

echo.
echo ====================================
echo   Servers are starting...
echo   Backend:  http://localhost:8080
echo   Frontend: http://localhost:3002
echo ====================================
echo.
echo Press any key to open browser...
pause >nul

start http://localhost:3002

echo.
echo Servers are running in separate windows.
echo Close those windows to stop the servers.
echo.
pause
