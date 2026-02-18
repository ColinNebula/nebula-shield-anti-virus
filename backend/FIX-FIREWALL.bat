@echo off
echo.
echo ========================================
echo   FIXING PORT 8080 FIREWALL ACCESS
echo ========================================
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo ERROR: This script must be run as Administrator!
    echo.
    echo Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo Removing old firewall rules...
netsh advfirewall firewall delete rule name="Nebula Shield Backend" >nul 2>&1
netsh advfirewall firewall delete rule name="Nebula Shield Backend Public" >nul 2>&1
netsh advfirewall firewall delete rule name="Node.js: Server-side JavaScript" >nul 2>&1

echo.
echo Adding new firewall rules for ALL network profiles...
echo.

REM Add rule for Private networks
netsh advfirewall firewall add rule name="Nebula Shield Backend" dir=in action=allow protocol=TCP localport=8080 profile=private
if %errorLevel% EQU 0 (
    echo [OK] Private network rule added
) else (
    echo [FAIL] Private network rule failed
)

REM Add rule for Public networks
netsh advfirewall firewall add rule name="Nebula Shield Backend Public" dir=in action=allow protocol=TCP localport=8080 profile=public
if %errorLevel% EQU 0 (
    echo [OK] Public network rule added
) else (
    echo [FAIL] Public network rule failed
)

REM Add rule for Domain networks
netsh advfirewall firewall add rule name="Nebula Shield Backend Domain" dir=in action=allow protocol=TCP localport=8080 profile=domain
if %errorLevel% EQU 0 (
    echo [OK] Domain network rule added
) else (
    echo [FAIL] Domain network rule failed
)

echo.
echo ========================================
echo   Testing Configuration
echo ========================================
echo.

REM Test if server is running
curl -s http://localhost:8080/api/status >nul 2>&1
if %errorLevel% EQU 0 (
    echo [OK] Backend server is running
) else (
    echo [WARN] Backend server not responding
    echo       Make sure to start it: node auth-server.js
)

echo.
echo Firewall rules configured!
echo.
echo ========================================
echo   NEXT STEPS:
echo ========================================
echo.
echo 1. Test on your phone browser:
echo    http://10.0.0.72:8080/api/status
echo.
echo 2. If that works, reload your Expo app:
echo    Shake phone ^> Tap "Reload"
echo.
echo 3. Try logging in again
echo.
echo ========================================
echo.
pause
