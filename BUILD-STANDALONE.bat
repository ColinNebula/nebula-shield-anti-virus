@echo off
:: Nebula Shield - Build Standalone Version
:: Simple wrapper for the PowerShell build script

echo.
echo ========================================
echo Nebula Shield Standalone Builder
echo ========================================
echo.
echo This will create a fully standalone version
echo that can be installed on other computers.
echo.
echo The build will include:
echo   - React Frontend
echo   - Backend Servers (Auth + API)
echo   - All dependencies bundled
echo   - Installer + Portable versions
echo.
echo Estimated time: 5-10 minutes
echo.
pause

echo.
echo Starting build process...
echo.

powershell -ExecutionPolicy Bypass -File "%~dp0build-standalone.ps1"

echo.
if %ERRORLEVEL% EQU 0 (
    echo ========================================
    echo Build completed successfully!
    echo ========================================
    echo.
    echo Check the 'dist' folder for output files.
    echo.
) else (
    echo ========================================
    echo Build failed! See errors above.
    echo ========================================
    echo.
)

pause
