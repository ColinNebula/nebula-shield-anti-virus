@echo off
REM Start all Nebula Shield servers
echo.
echo ================================================
echo  Nebula Shield - Starting All Servers
echo ================================================
echo.

REM Check if Node.js is installed
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Node.js is not installed or not in PATH
    pause
    exit /b 1
)

echo [1/2] Starting Backend Server on port 8080...
start "Nebula Shield - Backend Server" cmd /k "node backend/auth-server.js"
timeout /t 3 /nobreak >nul

echo [2/2] Starting Frontend Dev Server on port 3002...
start "Nebula Shield - Frontend Dev Server" cmd /k "npm run dev"

echo.
echo ================================================
echo  Servers Starting...
echo ================================================
echo.
echo Backend Server:  http://localhost:8080
echo Frontend Server: http://localhost:3002
echo.
echo Close the terminal windows to stop the servers
echo ================================================
echo.

pause
