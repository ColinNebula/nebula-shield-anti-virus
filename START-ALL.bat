@echo off
echo =========================================
echo    Nebula Shield - Starting All Servers
echo =========================================
echo.
echo Starting backend and React servers...
echo.

powershell.exe -ExecutionPolicy Bypass -File "%~dp0start-app.ps1"
