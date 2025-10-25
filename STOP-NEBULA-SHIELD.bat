@echo off
:: Nebula Shield Anti-Virus - Stop All Services
:: Double-click this file to stop all running servers

title Stop Nebula Shield Anti-Virus

powershell.exe -ExecutionPolicy Bypass -File "%~dp0stop-app.ps1"
