@echo off
echo.
echo ========================================
echo   Nebula Shield Mobile API Server
echo ========================================
echo.

cd /d "%~dp0backend"

echo Starting Mobile API Server...
node mobile-api-server.js

pause
