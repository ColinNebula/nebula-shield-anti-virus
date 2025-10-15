@echo off
echo Installing Nebula Shield Frontend Service...

nssm install NebulaShieldFrontend "C:\Program Files\nodejs\node.exe" "frontend-server\node_modules\serve\build\main.js" "-s frontend -l 3000"
nssm set NebulaShieldFrontend AppDirectory "%~dp0"
nssm set NebulaShieldFrontend DisplayName "Nebula Shield Frontend Server"
nssm set NebulaShieldFrontend Description "Web interface server"
nssm set NebulaShieldFrontend Start SERVICE_AUTO_START
nssm set NebulaShieldFrontend AppStdout "%~dp0data\logs\frontend-service.log"
nssm set NebulaShieldFrontend AppStderr "%~dp0data\logs\frontend-error.log"

echo Frontend service installed successfully!
pause
