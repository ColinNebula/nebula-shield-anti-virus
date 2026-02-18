@echo off
REM ========================================
REM NEBULA SHIELD ANTI-VIRUS
REM Complete Application Startup (Windows)
REM ========================================

echo.
echo Starting Nebula Shield Anti-Virus...
echo.

REM Check for PowerShell
where powershell >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: PowerShell not found!
    echo Please install PowerShell to run this script.
    pause
    exit /b 1
)

REM Run the PowerShell startup script
powershell -ExecutionPolicy Bypass -File "%~dp0START-COMPLETE-APP.ps1" %*

exit /b %ERRORLEVEL%
