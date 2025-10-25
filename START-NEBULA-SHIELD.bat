@echo off
:: Nebula Shield Anti-Virus - Quick Launcher
:: Double-click this file to start all servers and launch the app

title Nebula Shield Anti-Virus Launcher

:: Run the PowerShell startup script
powershell.exe -ExecutionPolicy Bypass -File "%~dp0start-app.ps1"

pause
