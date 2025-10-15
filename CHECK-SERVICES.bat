@echo off
REM Nebula Shield - Check Service Status
REM Built by Colin Nebula for Nebula3ddev.com

echo.
echo ╔════════════════════════════════════════════════╗
echo ║   Nebula Shield - Service Status Check        ║
echo ╚════════════════════════════════════════════════╝
echo.

powershell -NoProfile -Command ^
"$authStatus = $null; $backendStatus = $null; $frontendStatus = $null; " ^
"try { $auth = Invoke-WebRequest -Uri 'http://localhost:8082' -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue; $authStatus = 'RUNNING' } catch { $authStatus = 'NOT RUNNING' }; " ^
"try { $backend = Invoke-RestMethod -Uri 'http://localhost:8080/api/status' -TimeoutSec 2 -ErrorAction SilentlyContinue; if ($backend.status -eq 'running') { $backendStatus = 'RUNNING' } else { $backendStatus = 'ERROR' } } catch { $backendStatus = 'NOT RUNNING' }; " ^
"try { $frontend = Invoke-WebRequest -Uri 'http://localhost:3001' -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue; $frontendStatus = 'RUNNING' } catch { $frontendStatus = 'NOT RUNNING' }; " ^
"Write-Host ''; " ^
"Write-Host '🔐 Auth Server (Port 8082):' -NoNewline; " ^
"if ($authStatus -eq 'RUNNING') { Write-Host ' ✅ ' -ForegroundColor Green -NoNewline; Write-Host $authStatus -ForegroundColor Green } else { Write-Host ' ❌ ' -ForegroundColor Red -NoNewline; Write-Host $authStatus -ForegroundColor Red }; " ^
"Write-Host ''; " ^
"Write-Host '🛡️  Backend Server (Port 8080):' -NoNewline; " ^
"if ($backendStatus -eq 'RUNNING') { Write-Host ' ✅ ' -ForegroundColor Green -NoNewline; Write-Host $backendStatus -ForegroundColor Green } else { Write-Host ' ❌ ' -ForegroundColor Red -NoNewline; Write-Host $backendStatus -ForegroundColor Red }; " ^
"Write-Host ''; " ^
"Write-Host '🌐 Frontend (Port 3001):' -NoNewline; " ^
"if ($frontendStatus -eq 'RUNNING') { Write-Host ' ✅ ' -ForegroundColor Green -NoNewline; Write-Host $frontendStatus -ForegroundColor Green } else { Write-Host ' ❌ ' -ForegroundColor Red -NoNewline; Write-Host $frontendStatus -ForegroundColor Red }; " ^
"Write-Host ''; " ^
"if ($authStatus -eq 'RUNNING' -and $backendStatus -eq 'RUNNING' -and $frontendStatus -eq 'RUNNING') { Write-Host '✅ All services are running!' -ForegroundColor Green; Write-Host ''; Write-Host '🌐 Access Nebula Shield at: http://localhost:3001' -ForegroundColor Cyan } else { Write-Host '❌ Some services are not running!' -ForegroundColor Red; Write-Host ''; Write-Host '💡 To start all services, run: START-ALL-SERVICES.bat' -ForegroundColor Yellow }; " ^
"Write-Host ''"

echo.
pause
