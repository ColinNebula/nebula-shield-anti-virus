@echo off
echo ========================================
echo   Nebula Shield Service Installer
echo ========================================
echo.

REM Check for admin rights
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
) else (
    echo ERROR: This script requires administrator privileges!
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo Installing backend service...
call "%~dp0install-backend-service.bat"

echo.
echo Installing auth service...
call "%~dp0install-auth-service.bat"

echo.
echo Installing frontend service...
call "%~dp0install-frontend-service.bat"

echo.
echo Starting services...
nssm start NebulaShieldBackend
nssm start NebulaShieldAuth
nssm start NebulaShieldFrontend

echo.
echo ========================================
echo   Installation Complete!
echo ========================================
echo.
echo Services installed and started successfully.
echo You can now access Nebula Shield at:
echo http://localhost:3000
echo.
pause
