@echo off
echo ========================================
echo   Nebula Shield Service Uninstaller
echo ========================================
echo.

REM Check for admin rights
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
) else (
    echo ERROR: This script requires administrator privileges!
    pause
    exit /b 1
)

echo Stopping services...
nssm stop NebulaShieldBackend
nssm stop NebulaShieldAuth
nssm stop NebulaShieldFrontend

echo Removing services...
nssm remove NebulaShieldBackend confirm
nssm remove NebulaShieldAuth confirm
nssm remove NebulaShieldFrontend confirm

echo.
echo Services uninstalled successfully!
pause
