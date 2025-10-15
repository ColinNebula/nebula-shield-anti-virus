; Nebula Shield Antivirus - Inno Setup Script
; Creates a Windows installer with service installation

#define MyAppName "Nebula Shield Antivirus"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Nebula Shield Team"
#define MyAppURL "https://github.com/nebula-shield/antivirus"
#define MyAppExeName "Nebula Shield.bat"

[Setup]
; Basic Information
AppId={{B9C8F5D3-4A2E-4B7C-9F1A-3D8E6C5B4A2F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Nebula Shield
DefaultGroupName=Nebula Shield Antivirus
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
InfoBeforeFile=..\README.md
OutputDir=output
OutputBaseFilename=NebulaShield-Setup-{#MyAppVersion}
SetupIconFile=..\public\favicon.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

; Visual Settings
; Using default wizard images (commented out to avoid path issues)
; WizardImageFile=compiler:WizModernImage-IS.bmp
; WizardSmallImageFile=compiler:WizModernSmallImage-IS.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startservices"; Description: "Install and start Nebula Shield services"; GroupDescription: "Services:"; Flags: checkedonce

[Files]
; Backend Files
Source: "build\backend\*"; DestDir: "{app}\backend"; Flags: ignoreversion recursesubdirs createallsubdirs

; Auth Server Files
Source: "build\auth-server\*"; DestDir: "{app}\auth-server"; Flags: ignoreversion recursesubdirs createallsubdirs

; Frontend Server Files
Source: "build\frontend-server\*"; DestDir: "{app}\frontend-server"; Flags: ignoreversion recursesubdirs createallsubdirs

; Frontend Files
Source: "build\frontend\*"; DestDir: "{app}\frontend"; Flags: ignoreversion recursesubdirs createallsubdirs

; Data Directory
Source: "build\data\*"; DestDir: "{app}\data"; Flags: ignoreversion recursesubdirs createallsubdirs

; NSSM Service Manager
Source: "build\nssm.exe"; DestDir: "{app}"; Flags: ignoreversion

; Service Scripts
Source: "build\install-services.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\uninstall-services.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\install-backend-service.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\install-auth-service.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\install-frontend-service.bat"; DestDir: "{app}"; Flags: ignoreversion

; Launcher
Source: "build\Nebula Shield.bat"; DestDir: "{app}"; Flags: ignoreversion

; Documentation
Source: "build\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "build\SETTINGS_PERSISTENCE.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Nebula Shield Antivirus"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Nebula Shield Antivirus"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Install services if task is checked
Filename: "{app}\install-services.bat"; Description: "Install and start Nebula Shield services"; Flags: postinstall runhidden waituntilterminated; Tasks: startservices

; Open the application
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: postinstall nowait skipifsilent

[UninstallRun]
; Stop and remove services before uninstalling
Filename: "{app}\nssm.exe"; Parameters: "stop NebulaShieldBackend"; Flags: runhidden waituntilterminated
Filename: "{app}\nssm.exe"; Parameters: "stop NebulaShieldAuth"; Flags: runhidden waituntilterminated
Filename: "{app}\nssm.exe"; Parameters: "stop NebulaShieldFrontend"; Flags: runhidden waituntilterminated
Filename: "{app}\nssm.exe"; Parameters: "remove NebulaShieldBackend confirm"; Flags: runhidden waituntilterminated
Filename: "{app}\nssm.exe"; Parameters: "remove NebulaShieldAuth confirm"; Flags: runhidden waituntilterminated
Filename: "{app}\nssm.exe"; Parameters: "remove NebulaShieldFrontend confirm"; Flags: runhidden waituntilterminated

[Code]
function IsNodeJSInstalled(): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec('cmd.exe', '/C node --version', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

function InitializeSetup(): Boolean;
var
  DummyResultCode: Integer;
begin
  Result := True;
  
  if not IsNodeJSInstalled() then
  begin
    if MsgBox('Node.js is required but not installed. Would you like to download it now?', mbConfirmation, MB_YESNO) = IDYES then
    begin
      ShellExec('open', 'https://nodejs.org/en/download/', '', '', SW_SHOWNORMAL, ewNoWait, DummyResultCode);
      Result := False;
    end
    else
    begin
      MsgBox('Installation cannot continue without Node.js. Please install Node.js and try again.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if MsgBox('Do you want to delete all user data, including quarantined files and logs?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
    begin
      DelTree(ExpandConstant('{app}\data'), True, True, True);
    end;
  end;
end;
