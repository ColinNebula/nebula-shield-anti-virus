@echo off
echo ========================================
echo   Nebula Shield - Start All Services
echo ========================================
echo.

REM Start Backend in new window
echo Starting Backend Server...
start "Nebula Backend" cmd /k "cd /d %~dp0 && node mock-backend.js"
timeout /t 3 /nobreak >nul

REM Start React Dev Server in new window
echo Starting React Dev Server...
start "Nebula Frontend" cmd /k "cd /d %~dp0 && set BROWSER=none && npm start"
timeout /t 10 /nobreak >nul

REM Start Electron
echo Starting Electron...
start "Nebula Electron" cmd /k "cd /d %~dp0 && npm run electron:dev"

echo.
echo ========================================
echo   All services started!
echo   Backend: http://localhost:8080
echo   Frontend: http://localhost:3001
echo   Electron: Desktop App
echo ========================================
