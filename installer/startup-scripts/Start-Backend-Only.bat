@echo off
title Nebula Shield - Backend Services
echo Starting Nebula Shield Backend Services...
cd /d "%~dp0"

start "Auth Server" cmd /k "cd backend && node auth-server.js"
timeout /t 2 /nobreak >nul
start "Main Backend" cmd /k "node mock-backend.js"

echo.
echo Backend services started!
echo.
echo Auth Server: http://localhost:8082
echo Main Backend: http://localhost:8080
echo.
pause
