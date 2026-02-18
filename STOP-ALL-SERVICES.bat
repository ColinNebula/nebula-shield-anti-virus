@echo off
REM ========================================
REM NEBULA SHIELD ANTI-VIRUS
REM Stop All Services (Windows)
REM ========================================

echo.
echo Stopping Nebula Shield services...
echo.

REM Check for PowerShell
where powershell >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: PowerShell not found!
    echo Please install PowerShell to run this script.
    pause
    exit /b 1
)

REM Run the PowerShell stop script
powershell -ExecutionPolicy Bypass -File "%~dp0STOP-ALL-SERVICES.ps1"

exit /b %ERRORLEVEL%
