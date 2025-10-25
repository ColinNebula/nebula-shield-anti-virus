@echo off
echo ========================================
echo   Building Nebula Shield Production
echo ========================================
echo.

echo Step 1: Stopping any running processes...
taskkill /F /IM "Nebula Shield Anti-Virus.exe" 2>nul
taskkill /F /IM electron.exe 2>nul
timeout /t 2 /nobreak >nul

echo Step 2: Running Vite build...
call npm run build
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Vite build failed!
    pause
    exit /b 1
)

echo Step 3: Checking if production executable exists...
if not exist "dist\win-unpacked\Nebula Shield Anti-Virus.exe" (
    echo ERROR: Production executable not found!
    echo Please run: npm run electron:build:win
    echo Then try this script again.
    pause
    exit /b 1
)

echo Step 4: Copying build files to production app...
powershell -Command "Remove-Item 'dist\win-unpacked\resources\app.asar.unpacked\build\*' -Recurse -Force -ErrorAction SilentlyContinue; Copy-Item -Path 'build\*' -Destination 'dist\win-unpacked\resources\app.asar.unpacked\build\' -Recurse -Force"
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to copy files!
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Build Complete!
echo ========================================
echo.
echo Production files updated in:
echo   dist\win-unpacked\
echo.
echo To run the app, use:
echo   START-PRODUCTION-APP.bat
echo.
pause
