@echo off
echo Installing Nebula Shield Backend Service...

nssm install NebulaShieldBackend "%~dp0backend\nebula_shield_backend.exe"
nssm set NebulaShieldBackend AppDirectory "%~dp0"
nssm set NebulaShieldBackend DisplayName "Nebula Shield Antivirus Backend"
nssm set NebulaShieldBackend Description "Real-time antivirus protection engine"
nssm set NebulaShieldBackend Start SERVICE_AUTO_START
nssm set NebulaShieldBackend AppStdout "%~dp0data\logs\backend-service.log"
nssm set NebulaShieldBackend AppStderr "%~dp0data\logs\backend-error.log"

echo Backend service installed successfully!
pause
