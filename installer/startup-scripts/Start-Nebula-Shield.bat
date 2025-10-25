@echo off
title Nebula Shield Anti-Virus - All Services
echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║        🛡️  NEBULA SHIELD ANTI-VIRUS 🛡️                     ║
echo ║             Starting All Services...                      ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

cd /d "%~dp0"

REM Note: Using unified backend (mock-backend.js) which includes auth + all API endpoints
REM The auth-server.js is not needed as mock-backend.js provides authentication

echo Starting Unified Backend Server...
start "Nebula Shield - Backend" cmd /k "cd backend && node mock-backend.js"
timeout /t 5 /nobreak >nul

echo Starting Frontend...
start "Nebula Shield - Frontend" cmd /k "npm start"
timeout /t 2 /nobreak >nul

echo.
echo ✅ All services started!
echo.
echo The application will open automatically in your browser.
echo Browser URL: http://localhost:3001
echo.
echo To stop all services, close all terminal windows.
echo.
pause
