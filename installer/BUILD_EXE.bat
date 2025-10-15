@echo off
:: Build Nebula Shield Installer EXE
:: Created by Colin Nebula for Nebula3ddev.com

echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║     🛡️  NEBULA SHIELD - BUILD EXE INSTALLER 🛡️            ║
echo ║                                                           ║
echo ║         Built with ❤️  by Colin Nebula                    ║
echo ║                Nebula3ddev.com                           ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

:: Check if Inno Setup is installed
set "INNO_PATH=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"

if not exist "%INNO_PATH%" (
    echo ❌ Inno Setup not found!
    echo.
    echo Please install Inno Setup from:
    echo https://jrsoftware.org/isdl.php
    echo.
    echo After installation, run this script again.
    echo.
    pause
    exit /b 1
)

echo ✅ Inno Setup found!
echo.
echo 📦 Building installer EXE...
echo.

:: Compile the installer
"%INNO_PATH%" nebula-shield-setup.iss

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ╔═══════════════════════════════════════════════════════════╗
    echo ║                                                           ║
    echo ║          ✅  BUILD SUCCESSFUL! ✅                          ║
    echo ║                                                           ║
    echo ╚═══════════════════════════════════════════════════════════╝
    echo.
    echo 📦 Installer created:
    echo    output\NebulaShield-Setup-v1.0.0.exe
    echo.
    echo 🎉 You can now:
    echo    • Run the installer on this PC
    echo    • Copy to other Windows computers
    echo    • Share with users
    echo    • Distribute freely (MIT License)
    echo.
    echo 🎨 Features:
    echo    • ALL 9 logos included
    echo    • Desktop shortcut with icon
    echo    • Start Menu with icons
    echo    • Auto-installs dependencies
    echo    • Professional wizard interface
    echo.
    
    :: Ask if user wants to open the output folder
    set /p OPEN="Open output folder? (Y/N): "
    if /i "%OPEN%"=="Y" start explorer "output"
    
) else (
    echo.
    echo ❌ BUILD FAILED!
    echo.
    echo Check the error messages above.
    echo See BUILD_EXE_GUIDE.md for troubleshooting.
    echo.
)

pause
