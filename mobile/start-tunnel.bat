@echo off
cls
echo.
echo ========================================
echo   Nebula Shield Mobile - Expo SDK 54
echo   TUNNEL MODE (Works Anywhere)
echo ========================================
echo.
echo Starting Expo tunnel server...
echo Keep this window OPEN while testing!
echo.
cd /d "%~dp0"
node_modules\.bin\expo.cmd start --tunnel
pause
