@echo off
echo Starting Nebula Shield Backend Server...
cd backend
start "Nebula Shield Backend" /B node auth-server.js
echo Backend server started!
echo.
echo The server is running in the background.
echo To stop it, use STOP-BACKEND.bat or close this window.
pause
