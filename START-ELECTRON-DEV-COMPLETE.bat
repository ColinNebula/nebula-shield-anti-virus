@echo off
title Nebula Shield Anti-Virus - Development Mode
color 0B
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║        🛡️  NEBULA SHIELD ANTI-VIRUS - DEVELOPMENT 🛡️         ║
echo ║            Starting Development Environment...               ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

cd /d "%~dp0"

REM Check if backend is already running
echo [1/3] Checking for backend server...
netstat -ano | findstr ":8080.*LISTENING" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     ✅ Backend already running on port 8080
) else (
    echo     Starting backend server...
    start "Nebula Shield - Backend" /MIN cmd /k "cd backend && node mock-backend.js"
    echo     ⏳ Waiting for backend to start...
    timeout /t 5 /nobreak >nul
)

echo.
echo [2/3] Checking Vite dev server...
netstat -ano | findstr ":3002.*LISTENING" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     ✅ Vite dev server already running on port 3002
) else (
    echo     Starting Vite dev server...
    start "Nebula Shield - Vite Dev Server" /MIN cmd /k "npm run dev"
    echo     ⏳ Waiting for Vite to start (this may take a moment)...
    timeout /t 10 /nobreak >nul
)

echo.
echo [3/3] Launching Electron in development mode...
timeout /t 2 /nobreak >nul

REM Set environment variable to use Vite dev server
set ELECTRON_START_URL=http://localhost:3002
start "Nebula Shield - Electron Dev" cmd /k "npm run electron:dev"

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║               ✅ DEVELOPMENT MODE STARTED ✅                   ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo 📝 Services:
echo    🔧 Backend API:      http://localhost:8080
echo    🌐 Vite Dev Server:  http://localhost:3002
echo    💻 Electron App:     Using dev server (hot reload enabled)
echo.
echo 🔴 To stop all services, close all terminal windows
echo.
timeout /t 3

exit
