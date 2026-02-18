@echo off
echo ========================================
echo  Nebula Shield - Enable Mobile Access
echo ========================================
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo Adding Windows Firewall rule for port 8080...
netsh advfirewall firewall delete rule name="Nebula Shield Backend" >nul 2>&1
netsh advfirewall firewall add rule name="Nebula Shield Backend" dir=in action=allow protocol=TCP localport=8080

if %errorLevel% EQU 0 (
    echo ✓ Firewall rule added successfully!
) else (
    echo ✗ Failed to add firewall rule
)

echo.
echo Your PC's IP addresses:
echo.
ipconfig | findstr /i "IPv4"

echo.
echo ========================================
echo Next steps:
echo 1. Note your Wi-Fi IP address above
echo 2. Update apiClient.js with this IP
echo 3. Make sure phone is on same Wi-Fi
echo 4. Test from phone browser: http://YOUR-IP:8080/api/status
echo ========================================
echo.
pause
