@echo off
title Nebula Shield Anti-Virus - All Services
echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║        🛡️  NEBULA SHIELD ANTI-VIRUS 🛡️                     ║
echo ║             Starting All Services...                      ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

cd /d "%~dp0"

echo Starting Authentication Server...
start "Nebula Shield - Auth Server" cmd /k "cd backend && node auth-server.js"
timeout /t 3 /nobreak >nul

echo Starting Main Backend...
start "Nebula Shield - Backend" cmd /k "node mock-backend.js"
timeout /t 3 /nobreak >nul

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
