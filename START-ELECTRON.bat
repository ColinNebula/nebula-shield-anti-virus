@echo off
echo =========================================
echo    Nebula Shield - Electron Desktop App
echo =========================================
echo.
echo Starting Backend Server...
start /B "Nebula Backend" cmd /c "node mock-backend.js"

echo Waiting for backend to start...
timeout /t 3 /nobreak >nul

echo.
echo Starting React Dev Server and Electron...
echo.

REM Use npm's electron:dev which starts React dev server and waits for it
npm run electron:dev
