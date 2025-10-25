@echo off
echo =========================================
echo    Nebula Shield - Electron (Production)
echo =========================================
echo.
echo Starting backend server...
echo.

REM Start backend in background (using the auth server)
cd backend
start /B "Nebula Backend" node auth-server.js
cd ..

echo Waiting for backend to start...
timeout /t 5 /nobreak >nul

echo.
echo Starting Electron app...
echo.

REM Run Electron
npm run electron

