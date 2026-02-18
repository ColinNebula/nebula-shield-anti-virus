@echo off
REM Nebula Shield Backend Launcher with VPN Support
REM This starts the auth-server.js which includes all VPN endpoints

echo.
echo ========================================
echo   NEBULA SHIELD BACKEND LAUNCHER
echo   WITH VPN SUPPORT
echo ========================================
echo.

REM Kill any existing backend on port 8080
echo [1/3] Stopping existing backend...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8080') do (
    taskkill /F /PID %%a >nul 2>&1
)
timeout /t 2 /nobreak >nul

REM Navigate to backend directory
cd /d "%~dp0backend"

REM Start the backend with VPN support
echo [2/3] Starting backend with VPN endpoints...
echo.
echo Backend Features:
echo   - Authentication (Login/Register/Password Reset)
echo   - VPN Servers (12+ locations worldwide)
echo   - Network Protection
echo   - Scan Management
echo   - Quarantine Management
echo   - Disk Cleanup
echo.
echo Backend will run on: http://localhost:8080
echo VPN API: http://localhost:8080/api/vpn/servers
echo.
echo [3/3] Backend starting...
echo.
echo ========================================
echo   Press Ctrl+C to stop the backend
echo ========================================
echo.

REM Start the auth server
node auth-server.js
