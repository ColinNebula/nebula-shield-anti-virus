@echo off
echo ========================================
echo   Nebula Shield Anti-Virus - PRODUCTION
echo ========================================
echo.

REM Change to project directory
cd /d "%~dp0"

echo Starting Backend Server...
start "Nebula Shield Backend" cmd /k "cd backend && node mock-backend.js"

echo Waiting for backend to initialize...
timeout /t 5 /nobreak >nul

echo Starting Nebula Shield Application...
start "" "dist\win-unpacked\Nebula Shield Anti-Virus.exe"

echo.
echo ========================================
echo   Application Started!
echo ========================================
echo.
echo Backend API: http://localhost:8080
echo.
echo Login Credentials:
echo   Email: colinnebula@gmail.com
echo   Password: Nebula2025!
echo.
echo   OR
echo.
echo   Email: admin@test.com
echo   Password: admin
echo.
echo Press any key to close this window...
pause >nul
