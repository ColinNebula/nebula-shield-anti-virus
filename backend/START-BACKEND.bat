@echo off
echo Starting Nebula Shield Backend Server...
echo.
cd /d "%~dp0"
node auth-server.js
pause
