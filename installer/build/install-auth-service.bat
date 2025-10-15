@echo off
echo Installing Nebula Shield Auth Service...

nssm install NebulaShieldAuth "C:\Program Files\nodejs\node.exe" "auth-server\auth-server.js"
nssm set NebulaShieldAuth AppDirectory "%~dp0"
nssm set NebulaShieldAuth DisplayName "Nebula Shield Auth Server"
nssm set NebulaShieldAuth Description "User authentication and settings management"
nssm set NebulaShieldAuth Start SERVICE_AUTO_START
nssm set NebulaShieldAuth AppStdout "%~dp0data\logs\auth-service.log"
nssm set NebulaShieldAuth AppStderr "%~dp0data\logs\auth-error.log"

echo Auth service installed successfully!
pause
