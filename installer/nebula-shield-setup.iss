; Nebula Shield Anti-Virus - Professional Installer
; Created by Colin Nebula for Nebula3ddev.com
; Inno Setup Script

#define MyAppName "Nebula Shield Anti-Virus"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Colin Nebula - Nebula3ddev.com"
#define MyAppURL "https://nebula3ddev.com"
#define MyAppExeName "Start-Nebula-Shield.bat"

[Setup]
; Basic App Info
AppId={{B7F8E9D1-3C4A-4B5D-8E9F-1A2B3C4D5E6F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Installation Settings
DefaultDirName={autopf}\Nebula Shield
DefaultGroupName=Nebula Shield
AllowNoIcons=yes
LicenseFile=..\LICENSE
InfoBeforeFile=installer-info.txt
OutputDir=output
OutputBaseFilename=NebulaShield-Setup-v{#MyAppVersion}
SetupIconFile=..\public\favicon.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

; Privileges
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Visual Settings (removed - using default)
;WizardImageFile=compiler:WizModernImage-IS.bmp
;WizardSmallImageFile=compiler:WizModernSmallImage-IS.bmp

; Uninstall Settings
UninstallDisplayIcon={app}\public\favicon.ico
UninstallDisplayName={#MyAppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Main application files
Source: "..\package.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\package-lock.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\.env.example"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\.env.production"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\mock-backend.js"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\mock-backend-secure.js"; DestDir: "{app}"; Flags: ignoreversion

; Source code directories
Source: "..\src\*"; DestDir: "{app}\src"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\backend\*"; DestDir: "{app}\backend"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "node_modules,data,quarantine_vault"

; Public folder with ALL LOGOS
Source: "..\public\*"; DestDir: "{app}\public"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\public\logo.svg"; DestDir: "{app}\public"; Flags: ignoreversion
Source: "..\public\logo192.png"; DestDir: "{app}\public"; Flags: ignoreversion
Source: "..\public\logo512.png"; DestDir: "{app}\public"; Flags: ignoreversion
Source: "..\public\logo-horizontal.svg"; DestDir: "{app}\public"; Flags: ignoreversion
Source: "..\public\logo192.svg"; DestDir: "{app}\public"; Flags: ignoreversion
Source: "..\public\logo32.svg"; DestDir: "{app}\public"; Flags: ignoreversion
Source: "..\public\favicon.ico"; DestDir: "{app}\public"; Flags: ignoreversion
Source: "..\public\mech2.png"; DestDir: "{app}\public"; Flags: ignoreversion
Source: "..\public\manifest.json"; DestDir: "{app}\public"; Flags: ignoreversion

; Documentation
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\INSTALLATION_COMPLETE.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}\installer"; Flags: ignoreversion
Source: "QUICKSTART.md"; DestDir: "{app}\installer"; Flags: ignoreversion

; Startup scripts
Source: "startup-scripts\*"; DestDir: "{app}"; Flags: ignoreversion

; Admin creation script
Source: "create-default-admin.js"; DestDir: "{app}\installer"; Flags: ignoreversion
Source: "FIRST-TIME-LOGIN.md"; DestDir: "{app}\installer"; Flags: ignoreversion isreadme

[Dirs]
Name: "{app}\backend\data"; Permissions: users-full
Name: "{app}\backend\quarantine_vault"; Permissions: users-full
Name: "{app}\backend\logs"; Permissions: users-full

[Icons]
; Start Menu shortcuts with logo icon
Name: "{group}\Nebula Shield"; Filename: "{app}\Start-Nebula-Shield.bat"; IconFilename: "{app}\public\favicon.ico"; Comment: "Launch Nebula Shield Anti-Virus"
Name: "{group}\Nebula Shield (Backend Only)"; Filename: "{app}\Start-Backend-Only.bat"; IconFilename: "{app}\public\favicon.ico"; Comment: "Start backend services only"
Name: "{group}\Build Production"; Filename: "{app}\Build-Production.bat"; IconFilename: "{app}\public\favicon.ico"; Comment: "Create production build"
Name: "{group}\Installation Folder"; Filename: "{app}"; IconFilename: "{sys}\shell32.dll"; IconIndex: 3
Name: "{group}\README"; Filename: "{app}\README.md"; IconFilename: "{sys}\shell32.dll"; IconIndex: 71
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"; IconFilename: "{sys}\shell32.dll"; IconIndex: 31

; Desktop shortcut with logo icon
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\Start-Nebula-Shield.bat"; IconFilename: "{app}\public\favicon.ico"; Tasks: desktopicon; Comment: "Launch Nebula Shield Anti-Virus"

[Run]
; Create .env file if it doesn't exist
Filename: "{cmd}"; Parameters: "/c copy ""{app}\.env.example"" ""{app}\.env"""; Flags: runhidden; StatusMsg: "Creating configuration file..."; Check: not FileExists(ExpandConstant('{app}\.env'))

; Install Node.js dependencies
Filename: "{cmd}"; Parameters: "/c npm install --production"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; StatusMsg: "Installing frontend dependencies (this may take a few minutes)..."; Check: CheckNodeInstalled

; Install backend dependencies
Filename: "{cmd}"; Parameters: "/c npm install --production"; WorkingDir: "{app}\backend"; Flags: runhidden waituntilterminated; StatusMsg: "Installing backend dependencies..."; Check: CheckNodeInstalled and DirExists(ExpandConstant('{app}\backend'))

; Initialize databases
Filename: "{cmd}"; Parameters: "/c node -e ""require('./quarantine-service.js')"""; WorkingDir: "{app}\backend"; Flags: runhidden waituntilterminated; StatusMsg: "Initializing databases..."; Check: CheckNodeInstalled

; Create default admin account
Filename: "{cmd}"; Parameters: "/c node ""{app}\installer\create-default-admin.js"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; StatusMsg: "Creating default administrator account..."; Check: CheckNodeInstalled

; Show first-time login instructions
Filename: "notepad.exe"; Parameters: """{app}\installer\FIRST-TIME-LOGIN.md"""; Flags: nowait postinstall skipifsilent; Description: "View login credentials and getting started guide"

; Option to launch application
Filename: "{app}\Start-Nebula-Shield.bat"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallDelete]
Type: filesandordirs; Name: "{app}\node_modules"
Type: filesandordirs; Name: "{app}\backend\node_modules"
Type: filesandordirs; Name: "{app}\backend\data"
Type: filesandordirs; Name: "{app}\backend\quarantine_vault"
Type: filesandordirs; Name: "{app}\backend\logs"
Type: files; Name: "{app}\.env"

[Code]
function CheckNodeInstalled: Boolean;
var
  ResultCode: Integer;
begin
  // Check if Node.js is installed by running 'node --version'
  Result := Exec('cmd.exe', '/c node --version', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if not Result or (ResultCode <> 0) then
  begin
    MsgBox('Node.js is not installed or not found in PATH.' + #13#10 + #13#10 +
           'Please install Node.js 18.0.0 or higher from:' + #13#10 +
           'https://nodejs.org/' + #13#10 + #13#10 +
           'After installing Node.js, run this installer again.', 
           mbError, MB_OK);
    Result := False;
  end
  else
    Result := True;
end;

procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel1.Caption := 'Welcome to Nebula Shield Anti-Virus Setup';
  WizardForm.WelcomeLabel2.Caption := 
    'This will install Nebula Shield Anti-Virus on your computer.' + #13#10 + #13#10 +
    'Professional Enterprise-Grade Security Suite' + #13#10 +
    'Built with ❤️ by Colin Nebula for Nebula3ddev.com' + #13#10 + #13#10 +
    'Version ' + '{#MyAppVersion}' + #13#10 + #13#10 +
    'Features:' + #13#10 +
    '• Real-time scanning with VirusTotal integration' + #13#10 +
    '• Quarantine system with AES-256 encryption' + #13#10 +
    '• Network protection with IDS' + #13#10 +
    '• Web & email protection' + #13#10 +
    '• ALL logos and branding included' + #13#10 + #13#10 +
    'Click Next to continue, or Cancel to exit Setup.';
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  
  // Check if Node.js is installed before proceeding
  if not CheckNodeInstalled then
  begin
    Result := False;
    Exit;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Show completion message
    Log('Installation completed successfully');
  end;
end;
