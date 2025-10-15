@echo off
:: Nebula Shield Anti-Virus - Easy Installer Launcher
:: This batch file automatically requests administrator privileges

echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║       🛡️  NEBULA SHIELD ANTI-VIRUS INSTALLER 🛡️           ║
echo ║                                                           ║
echo ║         Built with ❤️  by Colin Nebula                    ║
echo ║                Nebula3ddev.com                           ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.
echo Starting installer with administrator privileges...
echo.

:: Run PowerShell as Administrator
PowerShell -Command "Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -File ""%~dp0install-nebula-shield.ps1""' -Verb RunAs"

echo.
echo The installer will open in a new window with admin privileges.
echo.
pause
