@echo off
echo Stopping all Node.js backend processes...
taskkill /IM node.exe /F 2>nul
if %errorlevel% == 0 (
    echo ✅ Backend server stopped successfully
) else (
    echo No backend server was running
)
pause
