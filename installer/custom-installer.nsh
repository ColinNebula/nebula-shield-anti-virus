# Nebula Shield Anti-Virus - Custom NSIS Installer Script
# Advanced installer with additional features and checks

# Check for existing installation and running processes
Section "-PreInstall" SecPreInstall
    
    # Check if application is running
    FindProcDLL::FindProc "Nebula Shield Anti-Virus.exe"
    IntCmp $R0 1 0 notRunning
        MessageBox MB_OK|MB_ICONEXCLAMATION "Nebula Shield Anti-Virus is currently running. Please close the application and try again."
        Abort
    notRunning:
    
    # Check available disk space (minimum 500MB)
    ${GetRoot} "$INSTDIR" $0
    ${DriveSpace} "$0" "/D=F /S=M" $1
    IntCmp $1 500 diskSpaceOK diskSpaceOK 0
        MessageBox MB_OK|MB_ICONEXCLAMATION "Insufficient disk space. At least 500MB is required."
        Abort
    diskSpaceOK:
    
    # Create application data directory
    CreateDirectory "$APPDATA\Nebula Shield"
    CreateDirectory "$APPDATA\Nebula Shield\logs"
    CreateDirectory "$APPDATA\Nebula Shield\quarantine"
    CreateDirectory "$APPDATA\Nebula Shield\data"
    
SectionEnd

# Post-installation setup
Section "-PostInstall" SecPostInstall
    
    # Set file permissions
    AccessControl::GrantOnFile "$INSTDIR" "(S-1-5-32-545)" "GenericRead + GenericExecute"
    AccessControl::GrantOnFile "$APPDATA\Nebula Shield" "(S-1-5-32-545)" "FullAccess"
    
    # Install Visual C++ Redistributables if needed
    ReadRegStr $0 HKLM "SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64" "Installed"
    IntCmp $0 1 vcRedistInstalled
        File /oname=$TEMP\vc_redist.x64.exe "installer\assets\vc_redist.x64.exe"
        ExecWait '"$TEMP\vc_redist.x64.exe" /quiet /norestart' $1
        Delete "$TEMP\vc_redist.x64.exe"
    vcRedistInstalled:
    
    # Register file associations for quarantine files
    WriteRegStr HKCR ".nqf" "" "NebulaQuarantineFile"
    WriteRegStr HKCR "NebulaQuarantineFile" "" "Nebula Shield Quarantine File"
    WriteRegStr HKCR "NebulaQuarantineFile\DefaultIcon" "" "$INSTDIR\${APPNAME}.exe,1"
    WriteRegStr HKCR "NebulaQuarantineFile\shell\open\command" "" '"$INSTDIR\${APPNAME}.exe" "%1"'
    
    # Create Windows Firewall exception
    nsExec::ExecToLog 'netsh advfirewall firewall add rule name="Nebula Shield Anti-Virus" dir=in action=allow program="$INSTDIR\${APPNAME}.exe"'
    
    # Start the service if checkbox is checked
    ${If} $StartServiceCheckbox == ${BST_CHECKED}
        ExecWait '"$INSTDIR\${APPNAME}.exe" --install-service'
        ExecWait '"$INSTDIR\${APPNAME}.exe" --start-service'
    ${EndIf}
    
    # Register for Windows Security Center
    WriteRegStr HKLM "SOFTWARE\Microsoft\Security Center\Monitoring\NebulaShield" "DisableMonitoring" "1"
    
SectionEnd

# Custom page for service options
Var StartServiceCheckbox
Var CreateScheduledTaskCheckbox

Page custom ServiceOptionsPage ServiceOptionsPageLeave

Function ServiceOptionsPage
    nsDialogs::Create 1018
    Pop $0
    
    ${NSD_CreateLabel} 0 0 100% 12u "Service Configuration"
    
    ${NSD_CreateCheckBox} 0 20u 100% 10u "&Start Nebula Shield service automatically"
    Pop $StartServiceCheckbox
    ${NSD_Check} $StartServiceCheckbox
    
    ${NSD_CreateCheckBox} 0 35u 100% 10u "&Create scheduled scan task"
    Pop $CreateScheduledTaskCheckbox
    ${NSD_Check} $CreateScheduledTaskCheckbox
    
    ${NSD_CreateLabel} 0 55u 100% 20u "The service provides real-time protection and runs in the background. The scheduled task performs automatic system scans."
    
    nsDialogs::Show
FunctionEnd

Function ServiceOptionsPageLeave
    # Get checkbox states for use in post-install
    ${NSD_GetState} $StartServiceCheckbox $StartServiceCheckbox
    ${NSD_GetState} $CreateScheduledTaskCheckbox $CreateScheduledTaskCheckbox
FunctionEnd

# Uninstaller enhancements
Section "un.StopServices" un.SecStopServices
    
    # Stop running processes
    FindProcDLL::FindProc "Nebula Shield Anti-Virus.exe"
    IntCmp $R0 1 0 notRunning
        MessageBox MB_YESNO "Nebula Shield Anti-Virus is currently running. Stop the application?" IDYES stopApp IDNO skipStop
        stopApp:
            FindProcDLL::KillProc "Nebula Shield Anti-Virus.exe"
            Sleep 2000
        skipStop:
    notRunning:
    
    # Stop and remove service
    ExecWait '"$INSTDIR\${APPNAME}.exe" --stop-service'
    ExecWait '"$INSTDIR\${APPNAME}.exe" --uninstall-service'
    
    # Remove Windows Firewall exception
    nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="Nebula Shield Anti-Virus"'
    
    # Remove file associations
    DeleteRegKey HKCR ".nqf"
    DeleteRegKey HKCR "NebulaQuarantineFile"
    
    # Remove Security Center registration
    DeleteRegKey HKLM "SOFTWARE\Microsoft\Security Center\Monitoring\NebulaShield"
    
SectionEnd

# Pre-uninstall confirmation
Function un.onInit
    MessageBox MB_YESNO|MB_ICONQUESTION "Are you sure you want to completely remove Nebula Shield Anti-Virus and all of its components?" IDYES +2
    Abort
    
    # Ask about user data
    MessageBox MB_YESNO|MB_ICONQUESTION "Do you want to remove all user data, settings, and quarantined files?$\nThis action cannot be undone." IDNO +3
        RMDir /r "$APPDATA\Nebula Shield"
        DeleteRegKey HKCU "Software\Nebula Shield"
FunctionEnd

# Custom installer finish actions
Function .onInstSuccess
    # Create scheduled task if requested
    ${If} $CreateScheduledTaskCheckbox == ${BST_CHECKED}
        nsExec::ExecToLog 'schtasks /create /tn "Nebula Shield Quick Scan" /tr "$INSTDIR\${APPNAME}.exe --quick-scan" /sc daily /st 12:00 /f'
    ${EndIf}
    
    # Show completion message
    MessageBox MB_OK "Nebula Shield Anti-Virus has been successfully installed!$\n$\nKey Features:$\n• Real-time virus protection$\n• Advanced firewall$\n• Web protection$\n• Email security$\n• System optimization"
FunctionEnd