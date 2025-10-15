@echo off
echo =========================================
echo    Nebula Shield Production Builder
echo =========================================
echo.
echo Building Electron app for Windows...
echo.

npm run dist:win

if %errorlevel% equ 0 (
    echo.
    echo =========================================
    echo    Build Complete!
    echo =========================================
    echo.
    echo Check the 'dist' folder for installers
    pause
) else (
    echo.
    echo [ERROR] Build failed!
    pause
    exit /b 1
)
