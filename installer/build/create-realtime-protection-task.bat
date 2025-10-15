@echo off
REM Create scheduled task to auto-enable real-time protection

echo Creating scheduled task for real-time protection...

schtasks /create /tn "NebulaShield_EnableRealTimeProtection" /tr "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File \"C:\Program Files\Nebula Shield\enable-realtime-protection.ps1\"" /sc onstart /ru SYSTEM /f /delay 0000:10

if %ERRORLEVEL% EQU 0 (
    echo SUCCESS: Scheduled task created
    echo Real-time protection will auto-enable 10 seconds after system startup
) else (
    echo ERROR: Failed to create scheduled task
)

pause
