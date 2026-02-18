; Custom NSIS installer script for Nebula Shield Anti-Virus
; This script adds custom installation steps

!macro customInstall
  ; Create application data directory
  CreateDirectory "$APPDATA\Nebula Shield Anti-Virus"
  CreateDirectory "$APPDATA\Nebula Shield Anti-Virus\logs"
  CreateDirectory "$APPDATA\Nebula Shield Anti-Virus\quarantine"
  CreateDirectory "$APPDATA\Nebula Shield Anti-Virus\signatures"
  CreateDirectory "$APPDATA\Nebula Shield Anti-Virus\data"
  
  ; Create database directory
  CreateDirectory "$LOCALAPPDATA\Nebula Shield Anti-Virus\database"
  
  DetailPrint "Installing Nebula Shield Anti-Virus components..."
!macroend

!macro customUnInstall
  ; Ask if user wants to keep data
  MessageBox MB_YESNO|MB_ICONQUESTION "Do you want to remove all Nebula Shield data including quarantined files and settings? Click No to keep your data for future installations." IDYES removeData IDNO keepData
  
  removeData:
    RMDir /r "$APPDATA\Nebula Shield Anti-Virus"
    RMDir /r "$LOCALAPPDATA\Nebula Shield Anti-Virus"
    DetailPrint "All Nebula Shield data has been removed."
    Goto endUninstall
  
  keepData:
    DetailPrint "Keeping Nebula Shield data for future use."
  
  endUninstall:
!macroend
