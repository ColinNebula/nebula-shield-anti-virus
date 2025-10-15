@echo off
echo.
echo ============================================
echo   Nebula Shield - Signature Manager
echo   Created by Colin Nebula
echo ============================================
echo.
echo Choose an option:
echo.
echo   1. Check Signature Status
echo   2. Reload Signatures from JSON
echo   3. View Virus Definitions Guide
echo   4. Exit
echo.
set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" goto check
if "%choice%"=="2" goto reload
if "%choice%"=="3" goto guide
if "%choice%"=="4" goto end

:check
echo.
echo Checking signature database status...
echo.
node backend\scripts\check-signatures.js
echo.
pause
goto end

:reload
echo.
echo Reloading signatures from virus-signatures.json...
echo.
node backend\scripts\load-signatures.js
echo.
pause
goto end

:guide
echo.
echo Opening Virus Definitions Guide...
echo.
type VIRUS-DEFINITIONS-GUIDE.md | more
echo.
pause
goto end

:end
echo.
echo Thank you for using Nebula Shield!
echo.
