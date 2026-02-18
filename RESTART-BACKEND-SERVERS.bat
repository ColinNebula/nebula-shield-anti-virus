@echo off
REM Restart backend servers with correct port configuration

powershell -ExecutionPolicy Bypass -File "%~dp0RESTART-BACKEND-SERVERS.ps1"
