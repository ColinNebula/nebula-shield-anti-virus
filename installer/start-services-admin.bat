@echo off
echo =============================================
echo   Nebula Shield - Start Services
echo =============================================
echo.

cd /d "C:\Program Files\Nebula Shield"

echo Starting Auth Server...
nssm.exe start NebulaShieldAuth
timeout /t 2 /nobreak >nul

echo Starting Backend Service...
nssm.exe start NebulaShieldBackend
timeout /t 2 /nobreak >nul

echo.
echo =============================================
echo   Checking Service Status
echo =============================================
echo.

nssm.exe status NebulaShieldAuth
nssm.exe status NebulaShieldBackend
nssm.exe status NebulaShieldFrontend

echo.
echo =============================================
echo   Testing Endpoints
echo =============================================
echo.

echo Testing Auth Server (port 8081)...
curl -s http://localhost:8081/api/health
echo.

echo Testing Backend (port 8080)...
curl -s http://localhost:8080/api/status
echo.

echo Testing Frontend (port 3000)...
curl -s -I http://localhost:3000 | findstr "200"
echo.

echo =============================================
echo   All services started!
echo   Opening application at http://localhost:3000
echo =============================================
echo.

start http://localhost:3000

pause
