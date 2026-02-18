@echo off
REM Nebula Shield Mobile Development Launcher
REM Starts both Backend and Expo servers

echo.
echo ========================================
echo   NEBULA SHIELD MOBILE DEV LAUNCHER
echo ========================================
echo.

REM Check if backend is already running
netstat -ano | findstr :8080 >nul
if %errorlevel%==0 (
    echo Backend already running on port 8080
) else (
    echo Starting Backend in new window...
    start "Nebula Shield Backend" "%~dp0START-BACKEND-WITH-VPN.bat"
    timeout /t 8 /nobreak >nul
)

REM Check if Expo is already running
netstat -ano | findstr :8084 >nul
if %errorlevel%==0 (
    echo Expo already running on port 8084
) else (
    echo Starting Expo server in new window...
    cd /d "%~dp0mobile"
    start "Nebula Shield Expo" cmd /k "npx expo start --port 8084"
    timeout /t 5 /nobreak >nul
)

echo.
echo ========================================
echo   SERVERS STARTED!
echo ========================================
echo.
echo Backend:  http://10.0.0.72:8080
echo Expo:     exp://10.0.0.72:8084
echo.
echo VPN API Available:
echo   GET  /api/vpn/servers
echo   GET  /api/vpn/status
echo   POST /api/vpn/connect
echo.
echo Check the opened windows for QR codes
echo and server output.
echo.
pause
