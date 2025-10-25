@echo off
REM Production Threat Detection - Quick Test Script

echo.
echo ╔══════════════════════════════════════════════════════════╗
echo ║  Nebula Shield - Production Threat Detection Test       ║
echo ╚══════════════════════════════════════════════════════════╝
echo.
echo Starting threat detection test suite...
echo.

cd /d "%~dp0backend"
node test-threat-detection.js

echo.
echo ╔══════════════════════════════════════════════════════════╗
echo ║                  Test Complete                           ║
echo ╚══════════════════════════════════════════════════════════╝
echo.
pause
