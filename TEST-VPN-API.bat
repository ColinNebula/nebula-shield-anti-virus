@echo off
REM Test VPN API endpoints
setlocal enabledelayedexpansion

echo.
echo ========================================
echo   VPN API ENDPOINT TESTER
echo ========================================
echo.

REM Check if backend is running
netstat -ano | findstr :8080 >nul
if %errorlevel% neq 0 (
    echo [ERROR] Backend not running on port 8080!
    echo.
    echo Please run: START-BACKEND-WITH-VPN.bat
    echo.
    pause
    exit /b 1
)

echo [OK] Backend is running on port 8080
echo.
echo Testing VPN endpoints...
echo.

REM Test VPN servers endpoint using PowerShell
powershell -Command "$ProgressPreference = 'SilentlyContinue'; try { $response = Invoke-RestMethod -Uri 'http://localhost:8080/api/vpn/servers' -Method Get -TimeoutSec 5; Write-Host '[SUCCESS] VPN Servers Endpoint' -ForegroundColor Green; Write-Host ''; Write-Host 'Total Servers:' $response.servers.Count -ForegroundColor Cyan; Write-Host ''; Write-Host 'Recommended Server:' -ForegroundColor Yellow; Write-Host '  ' $response.recommended.flag $response.recommended.name; Write-Host '  Latency:' $response.recommended.latency'ms | Load:' $response.recommended.load'%%'; Write-Host ''; Write-Host 'All Servers:' -ForegroundColor Cyan; $response.servers | ForEach-Object { Write-Host '  ' $_.flag $_.name '-' $_.latency'ms' '(' $_.status ')' }; } catch { Write-Host '[FAILED] VPN Servers Endpoint' -ForegroundColor Red; Write-Host 'Error:' $_.Exception.Message -ForegroundColor Red; }"

echo.
echo ========================================
echo   VPN API Test Complete
echo ========================================
echo.
pause
