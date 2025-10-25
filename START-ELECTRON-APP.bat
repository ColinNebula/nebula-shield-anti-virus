@echo off
title Nebula Shield Anti-Virus - Electron App Launcher
color 0B
echo.
echo ================================================================
echo         NEBULA SHIELD ANTI-VIRUS - ELECTRON
echo              Production Application Launcher
echo ================================================================
echo.

REM Get the directory where this script is located
cd /d "%~dp0"

REM Check if backend is already running on port 8080
echo [1/3] Checking for backend server on port 8080...
netstat -ano | findstr ":8080.*LISTENING" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     Backend server already running on port 8080
) else (
    echo     Backend server not detected, starting now...
    echo.
    
    REM Start the unified backend (mock-backend.js)
    echo [2/3] Starting Backend Server (mock-backend.js)...
    start "Nebula Shield - Backend Server" /MIN cmd /k "cd backend && node mock-backend.js"
    
    REM Wait for backend to start
    echo     Waiting for backend to initialize...
    timeout /t 5 /nobreak >nul
    
    REM Verify backend started
    netstat -ano | findstr ":8080.*LISTENING" >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo     Backend server started successfully
    ) else (
        echo     Failed to start backend server!
        echo     Please check if Node.js is installed and port 8080 is available.
        pause
        exit /b 1
    )
)

echo.
echo [3/3] Launching Electron Application...

REM Check which executable exists
if exist "dist\win-unpacked\Nebula Shield Anti-Virus.exe" (
    echo     Using unpacked build...
    start "" "dist\win-unpacked\Nebula Shield Anti-Virus.exe"
) else if exist "dist\Nebula Shield Anti-Virus 0.1.0.exe" (
    echo     Using portable executable...
    start "" "dist\Nebula Shield Anti-Virus 0.1.0.exe"
) else (
    echo     No built Electron app found!
    echo.
    echo     Please build the app first using one of:
    echo       - npm run electron:build:win
    echo       - BUILD-ELECTRON-WIN.bat
    echo.
    pause
    exit /b 1
)

echo.
echo ================================================================
echo                     STARTUP COMPLETE
echo ================================================================
echo.
echo Application is starting...
echo Backend API: http://localhost:8080
echo The Electron app window will open shortly
echo.
echo To stop the backend server:
echo    Close the "Nebula Shield - Backend Server" window
echo.
timeout /t 3

exit
