@echo off
echo Starting Nebula Shield Mobile API Server...
echo.
echo Make sure Windows Firewall allows Node.js on port 3001
echo Your mobile device should connect to: http://10.0.0.72:3001/api
echo.
cd /d "%~dp0"
node backend\mobile-api-server.js
pause
