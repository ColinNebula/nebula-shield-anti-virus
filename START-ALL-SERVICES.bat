@echo off
REM Nebula Shield - Start All Services
REM Built by Colin Nebula for Nebula3ddev.com

echo.
echo ╔════════════════════════════════════════════════╗
echo ║   Nebula Shield - Starting All Services       ║
echo ╚════════════════════════════════════════════════╝
echo.

REM Get current directory
set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

echo Starting Auth Server (Port 8082)...
start "Nebula Shield - Auth Server" powershell -NoExit -Command "cd '%PROJECT_DIR%backend'; node auth-server.js"
timeout /t 2 /nobreak >nul

echo Starting Backend Server (Port 8080)...
start "Nebula Shield - Backend" powershell -NoExit -Command "cd '%PROJECT_DIR%'; node mock-backend.js"
timeout /t 2 /nobreak >nul

echo Starting Frontend (Port 3001)...
start "Nebula Shield - Frontend" powershell -NoExit -Command "cd '%PROJECT_DIR%'; npm start"
timeout /t 3 /nobreak >nul

echo.
echo ╔════════════════════════════════════════════════╗
echo ║          All Services Started!                 ║
echo ╠════════════════════════════════════════════════╣
echo ║                                                ║
echo ║  Auth Server:  http://localhost:8082          ║
echo ║  Backend:      http://localhost:8080          ║
echo ║  Frontend:     http://localhost:3001          ║
echo ║                                                ║
echo ║  Opening browser...                           ║
echo ║                                                ║
echo ╚════════════════════════════════════════════════╝
echo.

timeout /t 5 /nobreak >nul
start http://localhost:3001

echo.
echo Press any key to close this window (services will keep running)...
pause >nul
