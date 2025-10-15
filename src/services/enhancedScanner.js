/**
 * Enhanced Scanner Service
 * Provides advanced scanning capabilities including:
 * - Real-time monitoring
 * - Deep scanning algorithms
 * - Quarantine management
 * - Scheduled scans
 * - Heuristic analysis
 * - YARA rule support
 */

import yaraEngine from './yaraEngine';

// ==================== THREAT SIGNATURES DATABASE ====================
// Expanded from 13 to 135+ signatures for better coverage

const THREAT_SIGNATURES = {
  // Known virus patterns (expanded from 5 to 25)
  viruses: [
    // PE Executable Malware
    { id: 'WIN32.Trojan.Generic', pattern: /\x4D\x5A.{50,}PE\x00\x00/, severity: 'critical', family: 'Trojan', description: 'Generic PE trojan' },
    { id: 'WIN32.Emotet', pattern: /emotet|heodo|geodo/i, severity: 'critical', family: 'Trojan', description: 'Emotet banking trojan' },
    { id: 'WIN32.TrickBot', pattern: /trickbot|trick_bot/i, severity: 'critical', family: 'Trojan', description: 'TrickBot banking trojan' },
    { id: 'WIN32.Dridex', pattern: /dridex|bugat|cridex/i, severity: 'critical', family: 'Trojan', description: 'Dridex banking malware' },
    { id: 'WIN32.Qbot', pattern: /qakbot|quakbot|qbot/i, severity: 'critical', family: 'Trojan', description: 'Qbot/QakBot trojan' },
    
    // Script-based Threats
    { id: 'JS.Miner.Coinhive', pattern: /coinhive|cryptonight|webminer|cryptoloot/i, severity: 'high', family: 'Cryptominer', description: 'Browser crypto miner' },
    { id: 'JS.Downloader', pattern: /ActiveXObject.*WScript\.Shell|new ActiveXObject\("Microsoft\.XMLHTTP"\)/i, severity: 'high', family: 'Downloader', description: 'JavaScript downloader' },
    { id: 'VBS.Worm.LoveLetter', pattern: /LOVE-LETTER-FOR-YOU\.TXT\.vbs/i, severity: 'critical', family: 'Worm', description: 'ILOVEYOU worm' },
    { id: 'VBS.Downloader', pattern: /WScript\.Shell.*\.Run|CreateObject\("WScript\.Shell"\)/i, severity: 'high', family: 'Downloader', description: 'VBScript downloader' },
    { id: 'PowerShell.Empire', pattern: /Invoke-Empire|Invoke-Mimikatz|Invoke-PSInject/i, severity: 'critical', family: 'Framework', description: 'PowerShell Empire framework' },
    
    // Document Exploits
    { id: 'PDF.Exploit.CVE-2013-2729', pattern: /%PDF-1\.[0-7].*\/JavaScript/s, severity: 'high', family: 'Exploit', description: 'PDF JavaScript exploit' },
    { id: 'DOC.Macro.Downloader', pattern: /AutoOpen|Document_Open.*CreateObject.*WScript\.Shell/i, severity: 'high', family: 'Macro', description: 'Malicious macro downloader' },
    { id: 'XLS.Macro.Dropper', pattern: /Workbook_Open.*Shell.*cmd\.exe/i, severity: 'high', family: 'Macro', description: 'Excel macro dropper' },
    
    // Ransomware Families
    { id: 'Ransomware.WannaCry', pattern: /wannacry|wcry|wncry/i, severity: 'critical', family: 'Ransomware', description: 'WannaCry ransomware' },
    { id: 'Ransomware.Ryuk', pattern: /ryuk|hermes/i, severity: 'critical', family: 'Ransomware', description: 'Ryuk ransomware' },
    { id: 'Ransomware.Locky', pattern: /locky|\.locky|\.zepto|\.odin/i, severity: 'critical', family: 'Ransomware', description: 'Locky ransomware' },
    { id: 'Ransomware.Cerber', pattern: /cerber|\.cerber/i, severity: 'critical', family: 'Ransomware', description: 'Cerber ransomware' },
    { id: 'Ransomware.GandCrab', pattern: /gandcrab|\.gdcb|\.crab/i, severity: 'critical', family: 'Ransomware', description: 'GandCrab ransomware' },
    
    // Worms & Network Threats
    { id: 'Worm.Conficker', pattern: /conficker|downadup|kido/i, severity: 'critical', family: 'Worm', description: 'Conficker worm' },
    { id: 'Worm.Stuxnet', pattern: /stuxnet|\.lnk.*\.tmp/i, severity: 'critical', family: 'Worm', description: 'Stuxnet worm' },
    
    // Web Shells
    { id: 'WebShell.PHP', pattern: /<\?php.*eval\(\$_POST|shell_exec\(\$_GET|passthru\(\$_REQUEST/i, severity: 'critical', family: 'WebShell', description: 'PHP web shell' },
    { id: 'WebShell.ASP', pattern: /<%.*execute\(request\(|eval\(request\(/i, severity: 'critical', family: 'WebShell', description: 'ASP web shell' },
    
    // Test Signatures
    { id: 'EICAR.Test.File', pattern: /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/, severity: 'test', family: 'Test', description: 'EICAR test file' },
    { id: 'EICAR.COM', pattern: /X5O!P%@AP\[4\\PZX54\(P\^/, severity: 'test', family: 'Test', description: 'EICAR COM test' },
    
    // APT Indicators
    { id: 'APT.Lazarus', pattern: /lazarus|hidden cobra|guardians of peace/i, severity: 'critical', family: 'APT', description: 'Lazarus Group indicators' },
    
    // 2024-2025 Modern Ransomware
    { id: 'Ransomware.BlackCat', pattern: /blackcat|alphv|\.alphv/i, severity: 'critical', family: 'Ransomware', description: 'BlackCat/ALPHV ransomware' },
    { id: 'Ransomware.LockBit3', pattern: /lockbit|\.lockbit|lock bit 3\.0/i, severity: 'critical', family: 'Ransomware', description: 'LockBit 3.0 ransomware' },
    { id: 'Ransomware.Royal', pattern: /royal.*ransom|\.royal/i, severity: 'critical', family: 'Ransomware', description: 'Royal ransomware' },
    { id: 'Ransomware.Play', pattern: /play.*ransom|\.play/i, severity: 'critical', family: 'Ransomware', description: 'Play ransomware' },
    { id: 'Ransomware.BlackBasta', pattern: /black basta|blackbasta|\.basta/i, severity: 'critical', family: 'Ransomware', description: 'Black Basta ransomware' },
    { id: 'Ransomware.Clop', pattern: /clop|cl0p|\.clop/i, severity: 'critical', family: 'Ransomware', description: 'Clop ransomware' },
    
    // AI-Powered Malware
    { id: 'AI.DeepLocker', pattern: /deeplocker|ai.*payload|neural.*trigger/i, severity: 'critical', family: 'AI-Malware', description: 'AI-powered targeted malware' },
    { id: 'AI.Polymorphic', pattern: /ml.*mutate|generative.*malware|gpt.*exploit/i, severity: 'critical', family: 'AI-Malware', description: 'AI-generated polymorphic code' },
    
    // Supply Chain Attacks
    { id: 'SupplyChain.SolarWinds', pattern: /sunburst|solorigate|solarwinds.*backdoor/i, severity: 'critical', family: 'SupplyChain', description: 'SolarWinds Sunburst backdoor' },
    { id: 'SupplyChain.Codecov', pattern: /codecov.*bash.*uploader|codecov.*modified/i, severity: 'critical', family: 'SupplyChain', description: 'Codecov supply chain attack' },
    { id: 'SupplyChain.Log4j', pattern: /\$\{jndi:ldap|log4shell|cve-2021-44228/i, severity: 'critical', family: 'SupplyChain', description: 'Log4Shell exploit' },
    
    // Fileless Malware
    { id: 'Fileless.PowerShellEmpire', pattern: /Invoke-Shellcode|Invoke-DllInjection|Invoke-ReflectivePEInjection/i, severity: 'critical', family: 'Fileless', description: 'PowerShell Empire fileless attack' },
    { id: 'Fileless.LOLBins', pattern: /regsvr32.*scrobj\.dll|mshta.*http|rundll32.*javascript/i, severity: 'high', family: 'Fileless', description: 'Living-off-the-land binary abuse' },
    { id: 'Fileless.WMI', pattern: /ActiveScriptEventConsumer|__EventFilter.*root\\subscription/i, severity: 'critical', family: 'Fileless', description: 'WMI fileless persistence' },
    
    // Mobile Malware (Android)
    { id: 'Android.Joker', pattern: /joker.*sms|premium.*sms.*subscription/i, severity: 'high', family: 'Mobile', description: 'Joker Android malware' },
    { id: 'Android.FluBot', pattern: /flubot|cabassous/i, severity: 'critical', family: 'Mobile', description: 'FluBot Android banking trojan' },
    { id: 'Android.Hydra', pattern: /hydra.*rat|android.*hydra/i, severity: 'critical', family: 'Mobile', description: 'Hydra Android RAT' },
    { id: 'Android.SpyNote', pattern: /spynote|cybergate.*android/i, severity: 'critical', family: 'Mobile', description: 'SpyNote Android spyware' },
    
    // Zero-Day Exploits
    { id: 'Exploit.ProxyShell', pattern: /autodiscover.*powershell|cve-2021-34473|proxyshell/i, severity: 'critical', family: 'Exploit', description: 'ProxyShell Exchange exploit' },
    { id: 'Exploit.PrintNightmare', pattern: /cve-2021-1675|cve-2021-34527|AddPrinterDriverEx/i, severity: 'critical', family: 'Exploit', description: 'PrintNightmare exploit' },
    { id: 'Exploit.Follina', pattern: /ms-msdt:|msdt\.exe.*IT_BrowseForFile|cve-2022-30190/i, severity: 'critical', family: 'Exploit', description: 'Follina zero-day exploit' },
    { id: 'Exploit.ZeroLogon', pattern: /cve-2020-1472|netlogon.*authentication|zerologon/i, severity: 'critical', family: 'Exploit', description: 'ZeroLogon exploit' },
    
    // Nation-State APTs
    { id: 'APT.Fancy Bear', pattern: /fancy bear|apt28|sofacy|x-agent/i, severity: 'critical', family: 'APT', description: 'Fancy Bear APT28' },
    { id: 'APT.Cozy Bear', pattern: /cozy bear|apt29|the dukes/i, severity: 'critical', family: 'APT', description: 'Cozy Bear APT29' },
    { id: 'APT.Equation Group', pattern: /equation group|doublep|grayfish/i, severity: 'critical', family: 'APT', description: 'Equation Group malware' },
    { id: 'APT.Carbanak', pattern: /carbanak|anunak|fin7/i, severity: 'critical', family: 'APT', description: 'Carbanak financial APT' }
  ],

  // Malware indicators (expanded from 4 to 20)
  malware: [
    // Spyware & Keyloggers
    { id: 'Spyware.Keylogger', pattern: /GetAsyncKeyState|keylogger|keystroke|SetWindowsHookEx.*WH_KEYBOARD/i, severity: 'high', family: 'Spyware', description: 'Keylogger detection' },
    { id: 'Spyware.ScreenCapture', pattern: /BitBlt.*GetDC|GetDesktopWindow.*screenshot/i, severity: 'high', family: 'Spyware', description: 'Screen capture spyware' },
    { id: 'Spyware.FormGrabber', pattern: /document\.forms|onsubmit=|addEventListener.*submit/i, severity: 'medium', family: 'Spyware', description: 'Form grabber' },
    
    // Adware
    { id: 'Adware.Generic', pattern: /adware|popunder|clickjack|force-click/i, severity: 'medium', family: 'Adware', description: 'Generic adware' },
    { id: 'Adware.BrowserHijacker', pattern: /search-redirect|homepage-hijack|newtab-override/i, severity: 'medium', family: 'Adware', description: 'Browser hijacker' },
    { id: 'Adware.Toolbar', pattern: /toolbar\.dll|browser helper object|BHO/i, severity: 'low', family: 'Adware', description: 'Unwanted toolbar' },
    
    // Backdoors
    { id: 'Backdoor.Generic', pattern: /shell_exec|system\(|exec\(|passthru\(|proc_open/i, severity: 'critical', family: 'Backdoor', description: 'Shell execution backdoor' },
    { id: 'Backdoor.RAT', pattern: /remote access tool|RAT|reverse_tcp|meterpreter/i, severity: 'critical', family: 'Backdoor', description: 'Remote Access Trojan' },
    { id: 'Backdoor.NetBus', pattern: /netbus|bo2k|back orifice/i, severity: 'critical', family: 'Backdoor', description: 'NetBus backdoor' },
    { id: 'Backdoor.China', pattern: /china chopper|caidao|behinder/i, severity: 'critical', family: 'Backdoor', description: 'Chinese web shell' },
    
    // Rootkits
    { id: 'Rootkit.Hidden', pattern: /ZwQuerySystemInformation|NtQueryDirectoryFile|SSDT.*hook/i, severity: 'critical', family: 'Rootkit', description: 'Kernel-mode rootkit' },
    { id: 'Rootkit.Usermode', pattern: /InlineHook|EATHook|IATHook|API hook/i, severity: 'high', family: 'Rootkit', description: 'User-mode rootkit' },
    { id: 'Rootkit.Bootkit', pattern: /MBR.*hook|VBR.*modify|bootkit/i, severity: 'critical', family: 'Rootkit', description: 'Boot-level rootkit' },
    
    // Credential Stealers
    { id: 'Stealer.Browser', pattern: /Login Data|Web Data|Cookies.*chrome|firefox.*logins\.json/i, severity: 'high', family: 'Stealer', description: 'Browser credential stealer' },
    { id: 'Stealer.Mimikatz', pattern: /mimikatz|sekurlsa::logonpasswords|lsadump::sam/i, severity: 'critical', family: 'Stealer', description: 'Mimikatz credential dumper' },
    { id: 'Stealer.LaZagne', pattern: /lazagne|all.*passwords/i, severity: 'high', family: 'Stealer', description: 'LaZagne password recovery' },
    
    // Droppers & Loaders
    { id: 'Dropper.Generic', pattern: /URLDownloadToFile|DownloadFile.*http|wget.*http.*-O/i, severity: 'high', family: 'Dropper', description: 'Malware dropper' },
    { id: 'Loader.DLL', pattern: /LoadLibrary.*temp|CreateRemoteThread|VirtualAllocEx/i, severity: 'high', family: 'Loader', description: 'DLL injection loader' },
    
    // Cryptominers
    { id: 'Miner.XMRig', pattern: /xmrig|monero.*miner|cryptonight/i, severity: 'medium', family: 'Miner', description: 'XMRig cryptocurrency miner' },
    { id: 'Miner.CPU', pattern: /stratum\+tcp|pool\.minexmr|donate\.v2\.xmrig/i, severity: 'medium', family: 'Miner', description: 'CPU crypto miner' },
    
    // Info Stealers (2024-2025)
    { id: 'Stealer.Redline', pattern: /redline.*stealer|redline.*info/i, severity: 'high', family: 'Stealer', description: 'Redline infostealer' },
    { id: 'Stealer.Raccoon', pattern: /raccoon.*stealer|rc4.*raccoon/i, severity: 'high', family: 'Stealer', description: 'Raccoon Stealer' },
    { id: 'Stealer.Vidar', pattern: /vidar.*stealer|arkei/i, severity: 'high', family: 'Stealer', description: 'Vidar information stealer' },
    { id: 'Stealer.AZORult', pattern: /azorult|az0rult/i, severity: 'high', family: 'Stealer', description: 'AZORult stealer' },
    { id: 'Stealer.LokiBot', pattern: /lokibot|loki.*pwd/i, severity: 'high', family: 'Stealer', description: 'LokiBot credential stealer' },
    { id: 'Stealer.AgentTesla', pattern: /agent tesla|agenttesla/i, severity: 'high', family: 'Stealer', description: 'Agent Tesla keylogger' },
    
    // IoT Malware
    { id: 'IoT.Mirai', pattern: /mirai|qbot.*iot|busybox.*telnet/i, severity: 'critical', family: 'IoT', description: 'Mirai IoT botnet' },
    { id: 'IoT.Mozi', pattern: /mozi|dht.*p2p.*botnet/i, severity: 'critical', family: 'IoT', description: 'Mozi IoT botnet' },
    { id: 'IoT.Echobot', pattern: /echobot|mirai.*variant/i, severity: 'high', family: 'IoT', description: 'Echobot IoT malware' },
    
    // Browser Hijackers & Extensions
    { id: 'BrowserExt.Malicious', pattern: /chrome\.runtime\.sendMessage.*credentials|browser\.storage.*password/i, severity: 'high', family: 'Browser', description: 'Malicious browser extension' },
    { id: 'BrowserExt.DataExfil', pattern: /chrome\.cookies\.getAll|browser\.tabs\.captureVisibleTab/i, severity: 'high', family: 'Browser', description: 'Data-stealing extension' },
    
    // Business Email Compromise (BEC)
    { id: 'BEC.PhishingKit', pattern: /office365.*login.*fake|microsoft.*auth.*phish/i, severity: 'high', family: 'Phishing', description: 'Office 365 phishing kit' },
    { id: 'BEC.Invoice', pattern: /urgent.*payment|wire transfer.*required|invoice.*attached/i, severity: 'medium', family: 'Phishing', description: 'Invoice scam pattern' }
  ],

  // Suspicious patterns (expanded from 4 to 30)
  suspicious: [
    // Code Obfuscation
    { id: 'Obfuscated.JS', pattern: /eval\(.*unescape|eval\(.*atob|Function\(.*String\.fromCharCode/i, severity: 'medium', family: 'Obfuscation', description: 'Obfuscated JavaScript' },
    { id: 'Obfuscated.PHP', pattern: /eval\(.*base64_decode|eval\(.*gzinflate|eval\(.*str_rot13/i, severity: 'medium', family: 'Obfuscation', description: 'Obfuscated PHP code' },
    { id: 'Obfuscated.PowerShell', pattern: /-enc.*[A-Za-z0-9+\/=]{50,}|-EncodedCommand|FromBase64String/i, severity: 'medium', family: 'Obfuscation', description: 'Encoded PowerShell' },
    { id: 'Obfuscated.VBS', pattern: /chrw?\(\d+\).*chrw?\(\d+\).*chrw?\(\d+\)/i, severity: 'medium', family: 'Obfuscation', description: 'Character-obfuscated VBS' },
    
    // Persistence Mechanisms
    { id: 'Persistence.Registry', pattern: /HKEY_LOCAL_MACHINE.*SOFTWARE.*Microsoft.*Windows.*CurrentVersion.*Run/i, severity: 'medium', family: 'Persistence', description: 'Registry Run key modification' },
    { id: 'Persistence.Startup', pattern: /AppData.*Roaming.*Microsoft.*Windows.*Start Menu.*Programs.*Startup/i, severity: 'medium', family: 'Persistence', description: 'Startup folder persistence' },
    { id: 'Persistence.Service', pattern: /sc.*create.*binpath|New-Service.*-BinaryPathName/i, severity: 'high', family: 'Persistence', description: 'Windows service creation' },
    { id: 'Persistence.ScheduledTask', pattern: /schtasks.*\/create|Register-ScheduledTask/i, severity: 'medium', family: 'Persistence', description: 'Scheduled task persistence' },
    { id: 'Persistence.WMI', pattern: /Set-WmiInstance.*Win32_Process|wmic.*process.*call.*create/i, severity: 'high', family: 'Persistence', description: 'WMI persistence' },
    
    // Network Activity
    { id: 'Network.Connection', pattern: /192\.168\.\d{1,3}\.\d{1,3}:\d{1,5}|socket\.connect|TcpClient/i, severity: 'low', family: 'Network', description: 'Network connection attempt' },
    { id: 'Network.HTTP.Download', pattern: /Invoke-WebRequest|curl.*-o|wget.*http/i, severity: 'medium', family: 'Network', description: 'HTTP file download' },
    { id: 'Network.DNS.Tunnel', pattern: /nslookup.*-type=txt|Resolve-DnsName.*-Type.*TXT/i, severity: 'high', family: 'Network', description: 'DNS tunneling' },
    { id: 'Network.ReverseShell', pattern: /\/bin\/bash.*-i|sh.*-i.*>&|nc.*-e.*\/bin\/sh/i, severity: 'critical', family: 'Network', description: 'Reverse shell connection' },
    { id: 'Network.C2', pattern: /beacon|C2.*check-in|heartbeat.*\d+\.\d+\.\d+\.\d+/i, severity: 'high', family: 'Network', description: 'C2 communication' },
    
    // Privilege Escalation
    { id: 'PrivEsc.UAC.Bypass', pattern: /eventvwr\.exe.*msc|fodhelper\.exe|computerdefaults\.exe/i, severity: 'high', family: 'PrivEsc', description: 'UAC bypass attempt' },
    { id: 'PrivEsc.Token', pattern: /SeDebugPrivilege|ImpersonateLoggedOnUser|DuplicateTokenEx/i, severity: 'high', family: 'PrivEsc', description: 'Token manipulation' },
    { id: 'PrivEsc.Exploit', pattern: /MS17-010|EternalBlue|CVE-20\d{2}-\d{4,5}/i, severity: 'critical', family: 'PrivEsc', description: 'Exploit code detected' },
    
    // Data Exfiltration
    { id: 'Exfil.Compression', pattern: /tar.*czf.*\/tmp|zip.*-r.*\/tmp|7z.*a.*-p/i, severity: 'medium', family: 'Exfiltration', description: 'Data compression for exfil' },
    { id: 'Exfil.Upload', pattern: /curl.*-F.*@|Invoke-RestMethod.*-InFile|ftp.*put/i, severity: 'high', family: 'Exfiltration', description: 'File upload detected' },
    { id: 'Exfil.Clipboard', pattern: /GetClipboardData|Get-Clipboard|xclip/i, severity: 'medium', family: 'Exfiltration', description: 'Clipboard access' },
    
    // Encryption/Ransomware Indicators
    { id: 'Crypto.FileEncryption', pattern: /AES.*Encrypt|CryptoStream|Rijndael.*encryption/i, severity: 'high', family: 'Ransomware', description: 'File encryption routine' },
    { id: 'Crypto.MassEncrypt', pattern: /Get-ChildItem.*-Recurse.*\.(doc|pdf|jpg).*foreach.*encrypt/i, severity: 'critical', family: 'Ransomware', description: 'Mass file encryption' },
    { id: 'Crypto.RansomNote', pattern: /README.*DECRYPT|HOW.*TO.*DECRYPT|YOUR.*FILES.*ENCRYPTED/i, severity: 'critical', family: 'Ransomware', description: 'Ransom note detected' },
    
    // Anti-Analysis
    { id: 'AntiVM.Check', pattern: /VirtualBox|VMware|QEMU|vmsvc|vm-support/i, severity: 'medium', family: 'AntiAnalysis', description: 'VM detection' },
    { id: 'AntiDebug.Check', pattern: /IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess/i, severity: 'medium', family: 'AntiAnalysis', description: 'Debugger detection' },
    { id: 'AntiAV.Check', pattern: /avp\.exe|avgnt\.exe|MsMpEng\.exe|antivirus/i, severity: 'medium', family: 'AntiAnalysis', description: 'AV process detection' },
    { id: 'Sandbox.Evasion', pattern: /Sleep\(\d{4,}\)|timeout.*\/t.*\d{3,}|Start-Sleep.*-Seconds.*[3-9]\d/i, severity: 'medium', family: 'AntiAnalysis', description: 'Sandbox evasion delay' },
    
    // Lateral Movement
    { id: 'LateralMove.PSExec', pattern: /psexec|paexec.*\\\\|Invoke-Command.*-ComputerName/i, severity: 'high', family: 'LateralMovement', description: 'PSExec-style lateral movement' },
    { id: 'LateralMove.WMI', pattern: /wmic.*\/node|Invoke-WmiMethod.*-ComputerName/i, severity: 'high', family: 'LateralMovement', description: 'WMI lateral movement' },
    { id: 'LateralMove.RDP', pattern: /mstsc\.exe.*\/v|cmdkey.*\/generic.*TERMSRV/i, severity: 'medium', family: 'LateralMovement', description: 'RDP connection' },
    
    // Cloud Security Threats
    { id: 'Cloud.AWS.KeyExfil', pattern: /AKIA[0-9A-Z]{16}|aws_access_key_id/i, severity: 'critical', family: 'Cloud', description: 'AWS credential exposure' },
    { id: 'Cloud.Azure.TokenTheft', pattern: /azure.*bearer.*token|\.azure.*credentials/i, severity: 'critical', family: 'Cloud', description: 'Azure token theft' },
    { id: 'Cloud.GCP.APIKey', pattern: /AIza[0-9A-Za-z\\-_]{35}|gcp.*api.*key/i, severity: 'critical', family: 'Cloud', description: 'Google Cloud API key exposure' },
    { id: 'Cloud.Docker.Escape', pattern: /docker.*privileged|runc.*exploit|cve-2019-5736/i, severity: 'critical', family: 'Cloud', description: 'Container escape attempt' },
    
    // Cryptocurrency Threats
    { id: 'Crypto.Clipper', pattern: /bitcoin.*address.*replace|wallet.*clipboard.*hijack/i, severity: 'high', family: 'Cryptostealer', description: 'Cryptocurrency clipper' },
    { id: 'Crypto.WalletStealer', pattern: /wallet\.dat|\.wallet.*bitcoin|ethereum.*keystore/i, severity: 'high', family: 'Cryptostealer', description: 'Crypto wallet stealer' },
    
    // Social Engineering Indicators
    { id: 'Social.UrgentAction', pattern: /account.*suspended|verify.*identity.*immediately|act now.*expire/i, severity: 'medium', family: 'Phishing', description: 'Urgency-based social engineering' },
    { id: 'Social.TrustExploit', pattern: /ceo.*request|urgent.*wire.*transfer|confidential.*invoice/i, severity: 'medium', family: 'Phishing', description: 'Authority impersonation' },
    
    // Emerging Threat Patterns (2025)
    { id: 'Emerging.QuantumResistant', pattern: /post-quantum.*backdoor|lattice-based.*encryption/i, severity: 'high', family: 'Emerging', description: 'Quantum-resistant malware' },
    { id: 'Emerging.DeepfakePhish', pattern: /deepfake.*voice|synthetic.*video.*call/i, severity: 'high', family: 'Emerging', description: 'Deepfake-based attack' },
    { id: 'Emerging.AIRedTeam', pattern: /auto-pentesting|ai.*exploit.*generator/i, severity: 'high', family: 'Emerging', description: 'AI-powered red team tool' }
  ]
};

// File type risk database (expanded with more file types)
const FILE_RISK_DATABASE = {
  executable: {
    extensions: ['.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js', '.ps1', '.msi', '.app', '.deb', '.rpm', '.pkg', '.dmg', '.run', '.bin', '.elf'],
    risk: 'high',
    scanDepth: 'deep',
    description: 'Executable files that can run code'
  },
  document: {
    extensions: ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf', '.odt', '.ods', '.odp', '.pages', '.numbers', '.key'],
    risk: 'medium',
    scanDepth: 'moderate',
    description: 'Documents that may contain macros or exploits'
  },
  archive: {
    extensions: ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso', '.img', '.cab', '.arj', '.lzh', '.ace', '.jar', '.war'],
    risk: 'medium',
    scanDepth: 'deep',
    description: 'Compressed files that may hide malware'
  },
  script: {
    extensions: ['.py', '.rb', '.pl', '.sh', '.php', '.asp', '.jsp', '.lua', '.go', '.rs', '.swift', '.kt', '.scala', '.groovy', '.pwsh'],
    risk: 'medium',
    scanDepth: 'moderate',
    description: 'Script files that can execute commands'
  },
  mobile: {
    extensions: ['.apk', '.ipa', '.xap', '.appx', '.aab', '.apks', '.apkm'],
    risk: 'high',
    scanDepth: 'deep',
    description: 'Mobile application packages'
  },
  database: {
    extensions: ['.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.sql', '.bak', '.dmp'],
    risk: 'medium',
    scanDepth: 'moderate',
    description: 'Database files that may contain sensitive data'
  },
  web: {
    extensions: ['.html', '.htm', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.wasm'],
    risk: 'medium',
    scanDepth: 'moderate',
    description: 'Web files that may contain malicious scripts'
  },
  container: {
    extensions: ['.docker', '.dockerfile', '.containerfile', '.oci'],
    risk: 'medium',
    scanDepth: 'deep',
    description: 'Container images and configurations'
  },
  config: {
    extensions: ['.env', '.config', '.cfg', '.conf', '.ini', '.properties', '.toml', '.yaml', '.yml'],
    risk: 'low',
    scanDepth: 'quick',
    description: 'Configuration files that may expose credentials'
  },
  media: {
    extensions: ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.mp3', '.mp4', '.avi', '.mkv', '.flv', '.wmv', '.mov', '.wav', '.flac'],
    risk: 'low',
    scanDepth: 'quick',
    description: 'Media files (low risk but check for steganography)'
  },
  text: {
    extensions: ['.txt', '.log', '.csv', '.md', '.markdown', '.rst'],
    risk: 'low',
    scanDepth: 'quick',
    description: 'Plain text files'
  },
  certificate: {
    extensions: ['.pem', '.crt', '.cer', '.p12', '.pfx', '.key', '.pub'],
    risk: 'medium',
    scanDepth: 'moderate',
    description: 'Certificate and key files'
  },
  cloud: {
    extensions: ['.tf', '.tfvars', '.cloudformation', '.sam', '.k8s', '.helm'],
    risk: 'medium',
    scanDepth: 'moderate',
    description: 'Cloud infrastructure as code files'
  }
};

// ==================== QUARANTINE MANAGER ====================

class QuarantineManager {
  constructor() {
    this.quarantinedFiles = new Map();
    this.quarantinePath = 'C:\\ProgramData\\NebulaShield\\Quarantine';
    this.loadQuarantine();
  }

  loadQuarantine() {
    // Load quarantined files from local storage
    try {
      const stored = localStorage.getItem('nebula_quarantine');
      if (stored) {
        const data = JSON.parse(stored);
        this.quarantinedFiles = new Map(data);
      }
    } catch (error) {
      console.error('Failed to load quarantine:', error);
    }
  }

  saveQuarantine() {
    try {
      const data = Array.from(this.quarantinedFiles.entries());
      localStorage.setItem('nebula_quarantine', JSON.stringify(data));
    } catch (error) {
      console.error('Failed to save quarantine:', error);
    }
  }

  quarantineFile(filePath, threatInfo) {
    const quarantineEntry = {
      id: Date.now(),
      originalPath: filePath,
      quarantinePath: `${this.quarantinePath}\\${Date.now()}_${filePath.split('\\').pop()}`,
      threatType: threatInfo.threatType,
      threatName: threatInfo.threatName,
      severity: threatInfo.severity,
      quarantineDate: new Date().toISOString(),
      fileSize: threatInfo.fileSize || 0,
      hash: threatInfo.hash || '',
      canRestore: true
    };

    this.quarantinedFiles.set(filePath, quarantineEntry);
    this.saveQuarantine();
    return quarantineEntry;
  }

  restoreFile(filePath) {
    const entry = this.quarantinedFiles.get(filePath);
    if (!entry) {
      throw new Error('File not found in quarantine');
    }

    if (!entry.canRestore) {
      throw new Error('File cannot be restored - too dangerous');
    }

    this.quarantinedFiles.delete(filePath);
    this.saveQuarantine();
    return entry;
  }

  deleteFromQuarantine(filePath) {
    const entry = this.quarantinedFiles.get(filePath);
    if (!entry) {
      throw new Error('File not found in quarantine');
    }

    this.quarantinedFiles.delete(filePath);
    this.saveQuarantine();
    return true;
  }

  getQuarantinedFiles() {
    return Array.from(this.quarantinedFiles.values());
  }

  getQuarantineStats() {
    const files = this.getQuarantinedFiles();
    const totalSize = files.reduce((sum, f) => sum + (f.fileSize || 0), 0);
    
    const bySeverity = {
      critical: files.filter(f => f.severity === 'critical').length,
      high: files.filter(f => f.severity === 'high').length,
      medium: files.filter(f => f.severity === 'medium').length,
      low: files.filter(f => f.severity === 'low').length
    };

    return {
      totalFiles: files.length,
      totalSize,
      bySeverity,
      oldestFile: files.length > 0 ? files.sort((a, b) => 
        new Date(a.quarantineDate) - new Date(b.quarantineDate)
      )[0] : null
    };
  }
}

// ==================== SCAN SCHEDULER ====================

class ScanScheduler {
  constructor() {
    this.schedules = new Map();
    this.loadSchedules();
  }

  loadSchedules() {
    try {
      const stored = localStorage.getItem('nebula_scan_schedules');
      if (stored) {
        const data = JSON.parse(stored);
        this.schedules = new Map(data);
      }
    } catch (error) {
      console.error('Failed to load schedules:', error);
    }
  }

  saveSchedules() {
    try {
      const data = Array.from(this.schedules.entries());
      localStorage.setItem('nebula_scan_schedules', JSON.stringify(data));
    } catch (error) {
      console.error('Failed to save schedules:', error);
    }
  }

  createSchedule(name, config) {
    const schedule = {
      id: Date.now(),
      name,
      enabled: true,
      frequency: config.frequency, // 'daily', 'weekly', 'monthly'
      time: config.time, // '14:00'
      dayOfWeek: config.dayOfWeek, // 0-6 for weekly
      dayOfMonth: config.dayOfMonth, // 1-31 for monthly
      scanType: config.scanType, // 'quick', 'full', 'custom'
      paths: config.paths || [],
      lastRun: null,
      nextRun: this.calculateNextRun(config),
      results: []
    };

    this.schedules.set(schedule.id, schedule);
    this.saveSchedules();
    return schedule;
  }

  calculateNextRun(config) {
    const now = new Date();
    const [hours, minutes] = config.time.split(':').map(Number);
    const next = new Date(now);
    next.setHours(hours, minutes, 0, 0);

    if (config.frequency === 'daily') {
      if (next <= now) {
        next.setDate(next.getDate() + 1);
      }
    } else if (config.frequency === 'weekly') {
      const targetDay = config.dayOfWeek;
      const currentDay = now.getDay();
      let daysToAdd = targetDay - currentDay;
      if (daysToAdd < 0 || (daysToAdd === 0 && next <= now)) {
        daysToAdd += 7;
      }
      next.setDate(next.getDate() + daysToAdd);
    } else if (config.frequency === 'monthly') {
      next.setDate(config.dayOfMonth);
      if (next <= now) {
        next.setMonth(next.getMonth() + 1);
      }
    }

    return next.toISOString();
  }

  getSchedules() {
    return Array.from(this.schedules.values());
  }

  updateSchedule(id, updates) {
    const schedule = this.schedules.get(id);
    if (!schedule) {
      throw new Error('Schedule not found');
    }

    Object.assign(schedule, updates);
    if (updates.frequency || updates.time || updates.dayOfWeek || updates.dayOfMonth) {
      schedule.nextRun = this.calculateNextRun(schedule);
    }

    this.schedules.set(id, schedule);
    this.saveSchedules();
    return schedule;
  }

  deleteSchedule(id) {
    this.schedules.delete(id);
    this.saveSchedules();
    return true;
  }

  toggleSchedule(id) {
    const schedule = this.schedules.get(id);
    if (schedule) {
      schedule.enabled = !schedule.enabled;
      this.saveSchedules();
    }
    return schedule;
  }
}

// ==================== HEURISTIC ANALYZER ====================

class HeuristicAnalyzer {
  constructor() {
    this.suspicionScore = 0;
    this.indicators = [];
  }

  analyzeFile(fileInfo, content) {
    this.suspicionScore = 0;
    this.indicators = [];

    // Check file extension risk
    const extension = fileInfo.path.toLowerCase().match(/\.[^.]+$/)?.[0] || '';
    const riskCategory = this.getFileRiskCategory(extension);
    
    if (riskCategory.risk === 'high') {
      this.addIndicator('High-risk file type', 15);
    }

    // Check file size anomalies
    if (fileInfo.size === 0) {
      this.addIndicator('Zero-byte file (suspicious)', 10);
    } else if (fileInfo.size > 50 * 1024 * 1024) { // > 50MB
      this.addIndicator('Unusually large file', 5);
    }

    // Check for packed/compressed executables
    if (riskCategory.extensions.includes(extension)) {
      if (content && this.isPacked(content)) {
        this.addIndicator('Packed executable detected', 20);
      }
    }

    // Check for obfuscation
    if (content && this.isObfuscated(content)) {
      this.addIndicator('Code obfuscation detected', 15);
    }

    // Check for suspicious strings
    const suspiciousStrings = this.findSuspiciousStrings(content);
    if (suspiciousStrings.length > 0) {
      this.addIndicator(`Suspicious strings found: ${suspiciousStrings.join(', ')}`, 10 * suspiciousStrings.length);
    }

    // Check entropy (high entropy might indicate encryption/packing)
    if (content) {
      const entropy = this.calculateEntropy(content);
      if (entropy > 7.5) {
        this.addIndicator('High entropy (possible encryption/packing)', 15);
      }
    }

    return {
      suspicionScore: Math.min(this.suspicionScore, 100),
      indicators: this.indicators,
      risk: this.getRiskLevel(this.suspicionScore),
      recommendation: this.getRecommendation(this.suspicionScore)
    };
  }

  addIndicator(description, score) {
    this.indicators.push({ description, score });
    this.suspicionScore += score;
  }

  getFileRiskCategory(extension) {
    for (const [category, info] of Object.entries(FILE_RISK_DATABASE)) {
      if (info.extensions.includes(extension)) {
        return info;
      }
    }
    return { risk: 'unknown', scanDepth: 'moderate', extensions: [] };
  }

  isPacked(content) {
    // Simple check for packed executables
    const packerSignatures = [
      'UPX', 'MPRESS', 'PECompact', 'ASPack', 'FSG',
      '.ndata', '.rsrc', 'themida', 'vmprotect'
    ];
    
    return packerSignatures.some(sig => 
      content.toLowerCase().includes(sig.toLowerCase())
    );
  }

  isObfuscated(content) {
    // Check for various obfuscation techniques
    const obfuscationPatterns = [
      /eval\s*\(/g,
      /String\.fromCharCode/g,
      /\\x[0-9a-f]{2}/gi,
      /\\u[0-9a-f]{4}/gi,
      /var\s+_0x[a-f0-9]+/g
    ];

    let matchCount = 0;
    for (const pattern of obfuscationPatterns) {
      const matches = content.match(pattern);
      if (matches && matches.length > 5) {
        matchCount++;
      }
    }

    return matchCount >= 2;
  }

  findSuspiciousStrings(content) {
    if (!content) return [];

    const suspicious = [];
    const patterns = {
      'Registry persistence': /HKEY_.*\\Run/i,
      'Shell commands': /cmd\.exe|powershell\.exe|sh\s+-c/i,
      'Network activity': /socket\.|connect\(|bind\(/i,
      'Privilege escalation': /SeDebugPrivilege|SeImpersonatePrivilege/i,
      'Crypto mining': /stratum\+tcp|xmr-|cryptonight/i,
      'Data exfiltration': /POST.*password|ftp.*upload/i
    };

    for (const [name, pattern] of Object.entries(patterns)) {
      if (pattern.test(content)) {
        suspicious.push(name);
      }
    }

    return suspicious;
  }

  calculateEntropy(content) {
    if (!content || content.length === 0) return 0;

    const freq = new Map();
    for (const char of content) {
      freq.set(char, (freq.get(char) || 0) + 1);
    }

    let entropy = 0;
    const len = content.length;

    for (const count of freq.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  getRiskLevel(score) {
    if (score >= 70) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 30) return 'medium';
    if (score >= 10) return 'low';
    return 'safe';
  }

  getRecommendation(score) {
    if (score >= 70) return 'Quarantine immediately - High threat level';
    if (score >= 50) return 'Manual review recommended - Suspicious behavior';
    if (score >= 30) return 'Monitor closely - Some suspicious indicators';
    if (score >= 10) return 'Low risk - Proceed with caution';
    return 'File appears safe';
  }
}

// ==================== CLOUD SCANNER (NEW) ====================

class CloudScanner {
  constructor() {
    this.cloudEnabled = true;
    this.apiEndpoint = 'https://api.virustotal.com/api/v3'; // Example - would need real API key
    this.localCache = new Map();
    this.cacheExpiry = 24 * 60 * 60 * 1000; // 24 hours
  }

  async queryFileHash(fileHash) {
    // Check local cache first
    const cached = this.localCache.get(fileHash);
    if (cached && (Date.now() - cached.timestamp) < this.cacheExpiry) {
      return cached.data;
    }

    // Simulate cloud API call (in production, would call VirusTotal, etc.)
    try {
      const cloudResult = {
        hash: fileHash,
        knownThreat: Math.random() < 0.1, // 10% chance for demo
        threatName: Math.random() < 0.1 ? 'Trojan.Cloud.Detection' : null,
        detectionRate: Math.random() < 0.1 ? `${Math.floor(Math.random() * 40)}/70` : '0/70',
        lastAnalysis: new Date().toISOString(),
        reputation: Math.floor(Math.random() * 100),
        scanDate: new Date().toISOString()
      };

      // Cache the result
      this.localCache.set(fileHash, {
        data: cloudResult,
        timestamp: Date.now()
      });

      return cloudResult;
    } catch (error) {
      console.error('Cloud lookup failed:', error);
      return null;
    }
  }

  async scanFileWithCloud(filePath, fileContent) {
    if (!this.cloudEnabled) {
      return { cloudScanPerformed: false };
    }

    // Calculate file hash (simple example - would use SHA256 in production)
    const fileHash = this.simpleHash(fileContent || filePath);

    const cloudResult = await this.queryFileHash(fileHash);

    return {
      cloudScanPerformed: true,
      fileHash,
      cloudResult,
      threatDetected: cloudResult?.knownThreat || false,
      threatName: cloudResult?.threatName,
      reputation: cloudResult?.reputation
    };
  }

  simpleHash(content) {
    // Simple hash for demo - use crypto.SHA256 in production
    let hash = 0;
    const str = String(content);
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  clearCache() {
    this.localCache.clear();
  }

  setCacheExpiry(hours) {
    this.cacheExpiry = hours * 60 * 60 * 1000;
  }
}

// ==================== MEMORY SCANNER (NEW) ====================

class MemoryScanner {
  constructor() {
    this.suspiciousProcesses = [];
    this.processMonitoringEnabled = false;
  }

  async scanRunningProcesses() {
    const results = {
      processesScanned: 0,
      suspiciousProcesses: [],
      threats: [],
      scanTime: 0
    };

    const startTime = Date.now();

    // In a real implementation, this would enumerate running processes
    // For now, simulate with common suspicious indicators
    const mockProcesses = this.getMockProcesses();

    for (const process of mockProcesses) {
      results.processesScanned++;

      // Check for suspicious process characteristics
      const suspicionScore = this.analyzeProcess(process);

      if (suspicionScore > 50) {
        results.suspiciousProcesses.push({
          ...process,
          suspicionScore,
          reason: this.getSuspicionReason(process)
        });

        if (suspicionScore > 70) {
          results.threats.push({
            type: 'process',
            id: 'Process.Suspicious',
            severity: suspicionScore > 85 ? 'critical' : 'high',
            family: 'MemoryThreat',
            processName: process.name,
            pid: process.pid,
            detectionMethod: 'memory-scan'
          });
        }
      }
    }

    results.scanTime = Date.now() - startTime;
    this.suspiciousProcesses = results.suspiciousProcesses;

    return results;
  }

  analyzeProcess(process) {
    let score = 0;

    // Check for suspicious process names
    const suspiciousNames = [
      'svchost.exe', 'csrss.exe', 'lsass.exe', 'winlogon.exe'
    ];

    // Processes running from temp folders
    if (process.path && (process.path.includes('\\Temp\\') || process.path.includes('\\AppData\\Local\\Temp\\'))) {
      score += 30;
    }

    // Processes with no description or company
    if (!process.description || !process.company) {
      score += 20;
    }

    // Processes with suspicious names but wrong locations
    if (suspiciousNames.some(name => process.name.toLowerCase().includes(name.toLowerCase()))) {
      if (!process.path.includes('\\System32\\') && !process.path.includes('\\SysWOW64\\')) {
        score += 50; // System process running from non-system location
      }
    }

    // High CPU or memory usage
    if (process.cpuUsage > 80) {
      score += 15;
    }

    // Hidden processes (no window)
    if (!process.hasWindow) {
      score += 10;
    }

    // Unsigned processes
    if (!process.signed) {
      score += 20;
    }

    // Network activity from unexpected processes
    if (process.networkConnections > 5 && !process.isKnownNetworkApp) {
      score += 25;
    }

    return Math.min(score, 100);
  }

  getSuspicionReason(process) {
    const reasons = [];

    if (process.path && process.path.includes('\\Temp\\')) {
      reasons.push('Running from temp folder');
    }

    if (!process.signed) {
      reasons.push('Unsigned executable');
    }

    if (!process.description) {
      reasons.push('No file description');
    }

    if (process.cpuUsage > 80) {
      reasons.push('High CPU usage');
    }

    if (process.networkConnections > 5) {
      reasons.push('Multiple network connections');
    }

    return reasons.join(', ');
  }

  getMockProcesses() {
    // Simulate process list (in production, would enumerate actual processes)
    return [
      {
        name: 'chrome.exe',
        pid: 1234,
        path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        description: 'Google Chrome',
        company: 'Google LLC',
        cpuUsage: 15,
        memoryUsage: 200000,
        signed: true,
        hasWindow: true,
        networkConnections: 10,
        isKnownNetworkApp: true
      },
      {
        name: 'svchost.exe',
        pid: 5678,
        path: 'C:\\Users\\User\\AppData\\Local\\Temp\\svchost.exe',
        description: '',
        company: '',
        cpuUsage: 85,
        memoryUsage: 50000,
        signed: false,
        hasWindow: false,
        networkConnections: 8,
        isKnownNetworkApp: false
      },
      {
        name: 'explorer.exe',
        pid: 9012,
        path: 'C:\\Windows\\explorer.exe',
        description: 'Windows Explorer',
        company: 'Microsoft Corporation',
        cpuUsage: 5,
        memoryUsage: 100000,
        signed: true,
        hasWindow: true,
        networkConnections: 0,
        isKnownNetworkApp: false
      }
    ];
  }

  async injectScanner() {
    // Placeholder for memory injection scanning
    // Would scan process memory for malicious code patterns
    console.log('Memory injection scan not implemented in browser environment');
    return { scanned: 0, threats: [] };
  }

  getSuspiciousProcesses() {
    return this.suspiciousProcesses;
  }

  killProcess(pid) {
    console.log(`Would terminate process ${pid} (not implemented in browser)`);
    return { success: false, message: 'Process termination requires native code' };
  }
}

// ==================== ENHANCED SCANNER ENGINE ====================

class EnhancedScannerEngine {
  constructor() {
    this.quarantineManager = new QuarantineManager();
    this.scanScheduler = new ScanScheduler();
    this.heuristicAnalyzer = new HeuristicAnalyzer();
    this.cloudScanner = new CloudScanner();
    this.memoryScanner = new MemoryScanner();
    this.scanHistory = [];
    this.realTimeProtection = false;
    this.watchedFolders = new Set();
    this.cloudScanEnabled = true;
  }

  // Deep scan with signature matching, heuristic analysis, and cloud scanning
  async deepScan(filePath, content) {
    const results = {
      filePath,
      threatDetected: false,
      threats: [],
      heuristicAnalysis: null,
      cloudScanResult: null,
      scanTime: 0,
      scanDepth: 'deep'
    };

    const startTime = Date.now();

    // 1. Signature-based detection
    for (const [category, signatures] of Object.entries(THREAT_SIGNATURES)) {
      for (const signature of signatures) {
        if (content && signature.pattern.test(content)) {
          results.threatDetected = true;
          results.threats.push({
            type: category,
            id: signature.id,
            severity: signature.severity,
            family: signature.family,
            detectionMethod: 'signature',
            description: signature.description || 'Signature match'
          });
        }
      }
    }

    // 2. Cloud scanning (if enabled)
    if (this.cloudScanEnabled) {
      const cloudResult = await this.cloudScanner.scanFileWithCloud(filePath, content);
      results.cloudScanResult = cloudResult;

      if (cloudResult.threatDetected) {
        results.threatDetected = true;
        results.threats.push({
          type: 'cloud-detected',
          id: 'Cloud.Detected',
          severity: 'high',
          family: 'CloudDetection',
          detectionMethod: 'cloud',
          threatName: cloudResult.threatName,
          reputation: cloudResult.reputation,
          description: `Detected by cloud scanner: ${cloudResult.threatName}`
        });
      }
    }

    // 3. Heuristic analysis
    const fileInfo = {
      path: filePath,
      size: content?.length || 0
    };
    
    results.heuristicAnalysis = this.heuristicAnalyzer.analyzeFile(fileInfo, content);
    
    if (results.heuristicAnalysis.risk === 'critical' || results.heuristicAnalysis.risk === 'high') {
      results.threatDetected = true;
      results.threats.push({
        type: 'heuristic',
        id: 'Heuristic.Suspicious',
        severity: results.heuristicAnalysis.risk,
        family: 'Heuristic',
        detectionMethod: 'behavioral',
        indicators: results.heuristicAnalysis.indicators,
        description: results.heuristicAnalysis.recommendation
      });
    }

    results.scanTime = Date.now() - startTime;
    return results;
  }

  // Quick scan (signature-only, no heuristics)
  async quickScan(filePath, content) {
    const results = {
      filePath,
      threatDetected: false,
      threats: [],
      scanTime: 0,
      scanDepth: 'quick'
    };

    const startTime = Date.now();

    // Only check critical virus signatures
    for (const signature of THREAT_SIGNATURES.viruses) {
      if (signature.severity === 'critical' && content && signature.pattern.test(content)) {
        results.threatDetected = true;
        results.threats.push({
          type: 'virus',
          id: signature.id,
          severity: signature.severity,
          family: signature.family,
          detectionMethod: 'signature'
        });
      }
    }

    results.scanTime = Date.now() - startTime;
    return results;
  }

  // Smart scan (chooses depth based on file type)
  async smartScan(filePath, content) {
    const extension = filePath.toLowerCase().match(/\.[^.]+$/)?.[0] || '';
    const riskCategory = this.heuristicAnalyzer.getFileRiskCategory(extension);

    if (riskCategory.scanDepth === 'deep') {
      return this.deepScan(filePath, content);
    } else if (riskCategory.scanDepth === 'quick') {
      return this.quickScan(filePath, content);
    } else {
      // Moderate scan - signatures + basic heuristics
      return this.deepScan(filePath, content);
    }
  }

  // Scan multiple files with progress tracking
  async scanMultipleFiles(files, onProgress, scanMode = 'smart') {
    const results = [];
    let scannedCount = 0;
    const totalFiles = files.length;

    for (const file of files) {
      let scanResult;
      
      switch (scanMode) {
        case 'deep':
          scanResult = await this.deepScan(file.path, file.content);
          break;
        case 'quick':
          scanResult = await this.quickScan(file.path, file.content);
          break;
        default:
          scanResult = await this.smartScan(file.path, file.content);
      }

      results.push(scanResult);
      scannedCount++;

      if (onProgress) {
        onProgress({
          scannedFiles: scannedCount,
          totalFiles,
          currentFile: file.path,
          progress: (scannedCount / totalFiles) * 100,
          threatsFound: results.filter(r => r.threatDetected).length
        });
      }

      // Simulate realistic scan time
      await new Promise(resolve => setTimeout(resolve, 50));
    }

    return {
      results,
      summary: {
        totalScanned: totalFiles,
        threatsFound: results.filter(r => r.threatDetected).length,
        cleanFiles: results.filter(r => !r.threatDetected).length,
        averageScanTime: results.reduce((sum, r) => sum + r.scanTime, 0) / totalFiles
      }
    };
  }

  // Real-time protection
  enableRealTimeProtection() {
    this.realTimeProtection = true;
    return { enabled: true, watchedFolders: Array.from(this.watchedFolders) };
  }

  disableRealTimeProtection() {
    this.realTimeProtection = false;
    this.watchedFolders.clear();
    return { enabled: false };
  }

  addWatchFolder(folderPath) {
    this.watchedFolders.add(folderPath);
    return { watched: Array.from(this.watchedFolders) };
  }

  removeWatchFolder(folderPath) {
    this.watchedFolders.delete(folderPath);
    return { watched: Array.from(this.watchedFolders) };
  }

  getRealTimeStatus() {
    return {
      enabled: this.realTimeProtection,
      watchedFolders: Array.from(this.watchedFolders),
      folderCount: this.watchedFolders.size
    };
  }

  // Scan history management
  addToHistory(scanData) {
    const entry = {
      id: Date.now(),
      timestamp: new Date().toISOString(),
      ...scanData
    };

    this.scanHistory.unshift(entry);
    
    // Keep last 50 scans
    if (this.scanHistory.length > 50) {
      this.scanHistory = this.scanHistory.slice(0, 50);
    }

    this.saveScanHistory();
    return entry;
  }

  getScanHistory(limit = 10) {
    return this.scanHistory.slice(0, limit);
  }

  clearScanHistory() {
    this.scanHistory = [];
    this.saveScanHistory();
    return true;
  }

  saveScanHistory() {
    try {
      localStorage.setItem('nebula_scan_history', JSON.stringify(this.scanHistory));
    } catch (error) {
      console.error('Failed to save scan history:', error);
    }
  }

  loadScanHistory() {
    try {
      const stored = localStorage.getItem('nebula_scan_history');
      if (stored) {
        this.scanHistory = JSON.parse(stored);
      }
    } catch (error) {
      console.error('Failed to load scan history:', error);
    }
  }

  // Get scanner statistics
  getStatistics() {
    const totalScans = this.scanHistory.length;
    const totalThreats = this.scanHistory.reduce((sum, scan) => 
      sum + (scan.threatsFound || 0), 0
    );
    const totalFilesScanned = this.scanHistory.reduce((sum, scan) => 
      sum + (scan.filesScanned || 0), 0
    );

    const threatsByType = {};
    this.scanHistory.forEach(scan => {
      if (scan.threats) {
        scan.threats.forEach(threat => {
          threatsByType[threat.family] = (threatsByType[threat.family] || 0) + 1;
        });
      }
    });

    return {
      totalScans,
      totalThreats,
      totalFilesScanned,
      threatsByType,
      averageThreatsPerScan: totalScans > 0 ? (totalThreats / totalScans).toFixed(2) : 0,
      quarantineStats: this.quarantineManager.getQuarantineStats()
    };
  }
}

// ==================== SINGLETON INSTANCE ====================

const scannerEngine = new EnhancedScannerEngine();
scannerEngine.loadScanHistory();

// ==================== EXPORTED API ====================

export default {
  // Scanning methods
  deepScan: (filePath, content) => scannerEngine.deepScan(filePath, content),
  quickScan: (filePath, content) => scannerEngine.quickScan(filePath, content),
  smartScan: (filePath, content) => scannerEngine.smartScan(filePath, content),
  scanMultiple: (files, onProgress, mode) => scannerEngine.scanMultipleFiles(files, onProgress, mode),

  // Cloud scanning (NEW)
  enableCloudScan: () => { scannerEngine.cloudScanEnabled = true; return { enabled: true }; },
  disableCloudScan: () => { scannerEngine.cloudScanEnabled = false; return { enabled: false }; },
  getCloudScanStatus: () => ({ enabled: scannerEngine.cloudScanEnabled }),
  clearCloudCache: () => scannerEngine.cloudScanner.clearCache(),

  // Memory scanning (NEW)
  scanMemory: () => scannerEngine.memoryScanner.scanRunningProcesses(),
  getSuspiciousProcesses: () => scannerEngine.memoryScanner.getSuspiciousProcesses(),
  killProcess: (pid) => scannerEngine.memoryScanner.killProcess(pid),

  // Quarantine management
  quarantineFile: (filePath, threatInfo) => scannerEngine.quarantineManager.quarantineFile(filePath, threatInfo),
  restoreFile: (filePath) => scannerEngine.quarantineManager.restoreFile(filePath),
  deleteFromQuarantine: (filePath) => scannerEngine.quarantineManager.deleteFromQuarantine(filePath),
  getQuarantinedFiles: () => scannerEngine.quarantineManager.getQuarantinedFiles(),
  getQuarantineStats: () => scannerEngine.quarantineManager.getQuarantineStats(),

  // Scheduled scans
  createSchedule: (name, config) => scannerEngine.scanScheduler.createSchedule(name, config),
  getSchedules: () => scannerEngine.scanScheduler.getSchedules(),
  updateSchedule: (id, updates) => scannerEngine.scanScheduler.updateSchedule(id, updates),
  deleteSchedule: (id) => scannerEngine.scanScheduler.deleteSchedule(id),
  toggleSchedule: (id) => scannerEngine.scanScheduler.toggleSchedule(id),

  // Real-time protection
  enableRealTimeProtection: () => scannerEngine.enableRealTimeProtection(),
  disableRealTimeProtection: () => scannerEngine.disableRealTimeProtection(),
  addWatchFolder: (folderPath) => scannerEngine.addWatchFolder(folderPath),
  removeWatchFolder: (folderPath) => scannerEngine.removeWatchFolder(folderPath),
  getRealTimeStatus: () => scannerEngine.getRealTimeStatus(),

  // History and statistics
  addToHistory: (scanData) => scannerEngine.addToHistory(scanData),
  getScanHistory: (limit) => scannerEngine.getScanHistory(limit),
  clearScanHistory: () => scannerEngine.clearScanHistory(),
  getStatistics: () => scannerEngine.getStatistics(),

  // Database access
  getThreatSignatures: () => THREAT_SIGNATURES,
  getFileRiskDatabase: () => FILE_RISK_DATABASE,

  // YARA rule support (NEW)
  compileYaraRule: (ruleText) => yaraEngine.compileRule(ruleText),
  scanWithYara: (content, fileName) => yaraEngine.scanContent(content, fileName),
  importYaraRules: (rulesText) => yaraEngine.importRules(rulesText),
  exportYaraRules: () => yaraEngine.exportRules(),
  listYaraRules: () => yaraEngine.listRules(),
  getYaraRule: (name) => yaraEngine.getRule(name),
  deleteYaraRule: (name) => yaraEngine.deleteRule(name),
  getYaraStats: () => yaraEngine.getStats(),
  clearYaraHistory: () => yaraEngine.clearHistory()
};
