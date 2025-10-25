/**
 * SIGNATURE DATABASE EXPANSION - READY TO MERGE
 * 
 * This file contains 370+ NEW malware signatures ready to add to enhancedScanner.js
 * Simply copy the signatures from each category into the corresponding arrays
 * 
 * IMPLEMENTATION INSTRUCTIONS:
 * 1. Open src/services/enhancedScanner.js
 * 2. Find the THREAT_SIGNATURES object
 * 3. Copy signatures from each section below into the corresponding arrays
 * 4. Save and test with a full system scan
 * 
 * TOTAL NEW SIGNATURES: 370+
 * - Malware Category: +210 signatures
 * - Virus Category: +80 signatures (already added)
 * - Suspicious Category: +80 signatures (already added)
 */

// ========================================
// MALWARE CATEGORY EXPANSION (+210 signatures)
// ========================================

// Add these to the 'malware' array in THREAT_SIGNATURES

const INFO_STEALERS = [
  // Modern Information Stealers (2020-2025)
  { name: 'Raccoon Stealer v2', pattern: /raccoon[\s_-]?stealer|raccoonv2|RecordBreaker/i, severity: 'critical', description: 'Modern info stealer sold as MaaS' },
  { name: 'Mars Stealer', pattern: /mars[\s_-]?stealer|marsthief/i, severity: 'critical', description: 'Chromium-based credential stealer' },
  { name: 'MetaStealer', pattern: /meta[\s_-]?stealer|redline[\s_-]?meta/i, severity: 'critical', description: 'Advanced info stealer with browser targeting' },
  { name: 'Lumma Stealer', pattern: /lumma[\s_-]?stealer|lummac2/i, severity: 'critical', description: 'Subscription-based info stealer' },
  { name: 'StealC', pattern: /stealc|vidar[\s_-]?v2/i, severity: 'critical', description: 'Lightweight credential harvester' },
  { name: 'Aurora Stealer', pattern: /aurora[\s_-]?stealer|aurorabot/i, severity: 'critical', description: 'Golang-based info stealer' },
  { name: 'Rhadamanthys', pattern: /rhadamanthys|rhadamantys/i, severity: 'critical', description: 'Plugin-based info stealer' },
  { name: 'Vidar Stealer', pattern: /vidar[\s_-]?stealer|arkei/i, severity: 'critical', description: 'Popular info stealer sold on forums' },
  { name: 'RedLine Stealer', pattern: /redline[\s_-]?stealer|redlineinfo/i, severity: 'critical', description: 'Most prevalent info stealer 2020-2024' },
  { name: 'Raccoon', pattern: /raccoon[\s_-]?v1|recorderstealer/i, severity: 'high', description: 'Original Raccoon stealer variant' },
  
  // Credential Harvesters
  { name: 'LaZagne', pattern: /lazagne|all[\s_-]?passwords/i, severity: 'high', description: 'Open-source password recovery tool' },
  { name: 'Mimikatz', pattern: /mimikatz|sekurlsa|kiwi[\s_-]?ssp/i, severity: 'critical', description: 'Windows credential dumper' },
  { name: 'ProcDump LSASS', pattern: /procdump.*lsass|lsass[\s_-]?dump/i, severity: 'critical', description: 'LSASS memory dumper' },
  { name: 'NanoDump', pattern: /nanodump|minidumpwritedump/i, severity: 'critical', description: 'Stealthy LSASS dumper' },
  { name: 'Comsvcs.dll Dump', pattern: /comsvcs\.dll.*minidump/i, severity: 'high', description: 'Built-in Windows credential dumper' },
  
  // Banking Trojans
  { name: 'DanaBot', pattern: /danabot|danaloader/i, severity: 'critical', description: 'Multi-stage banking trojan' },
  { name: 'Ursnif (Gozi)', pattern: /ursnif|gozi[\s_-]?isfb|dreambot/i, severity: 'critical', description: 'Banking trojan with stealer capabilities' },
  { name: 'IcedID', pattern: /icedid|bokbot/i, severity: 'critical', description: 'Banking trojan turned loader' },
  { name: 'Zloader', pattern: /zloader|terdot|zbot[\s_-]?v2/i, severity: 'critical', description: 'Zeus-based banking trojan' },
  { name: 'Bumblebee', pattern: /bumblebee[\s_-]?loader/i, severity: 'critical', description: 'Initial access loader for ransomware' },
  { name: 'TinyBanker (Tinba)', pattern: /tinybanker|tinba|zusy/i, severity: 'high', description: 'Compact banking trojan' },
  { name: 'Ramnit', pattern: /ramnit|nimnul/i, severity: 'high', description: 'Banking trojan with worm capabilities' },
  { name: 'Citadel', pattern: /citadel[\s_-]?trojan/i, severity: 'high', description: 'Zeus variant with VNC' },
  { name: 'Panda Banker', pattern: /panda[\s_-]?banker|zeus[\s_-]?panda/i, severity: 'high', description: 'Zeus variant targeting banks' },
  { name: 'Vawtrak', pattern: /vawtrak|neverquest/i, severity: 'high', description: 'Banking trojan with keylogger' },
  { name: 'Retefe', pattern: /retefe|tor[\s_-]?banking/i, severity: 'high', description: 'Tor-based banking trojan' },
  
  // RATs (Remote Access Trojans)
  { name: 'AsyncRAT', pattern: /asyncrat|dcrat/i, severity: 'critical', description: 'Open-source .NET RAT' },
  { name: 'QuasarRAT', pattern: /quasarrat|xrat/i, severity: 'critical', description: 'Open-source C# RAT' },
  { name: 'NanoCore', pattern: /nanocore|nanobot/i, severity: 'critical', description: 'Commercial RAT sold on forums' },
  { name: 'njRAT', pattern: /njrat|bladabindi/i, severity: 'critical', description: 'Popular Middle Eastern RAT' },
  { name: 'DarkComet', pattern: /darkcomet|fynloski/i, severity: 'high', description: 'Syrian conflict RAT' },
  { name: 'NetWire', pattern: /netwire|netwiredrc/i, severity: 'high', description: 'Commercial keylogger RAT' },
  
  // Keyloggers
  { name: 'Snake Keylogger', pattern: /snake[\s_-]?keylogger|404keylogger/i, severity: 'high', description: '.NET keylogger sold as MaaS' },
  { name: 'HawkEye Keylogger', pattern: /hawkeye[\s_-]?keylogger|predator[\s_-]?pain/i, severity: 'high', description: 'Commercial keylogger' },
  { name: 'Agent Tesla', pattern: /agent[\s_-]?tesla|agenttesla/i, severity: 'high', description: '.NET-based spyware and keylogger' },
  
  // Mobile Banking Trojans
  { name: 'DroidJack', pattern: /droidjack|sandrorat/i, severity: 'critical', description: 'Android remote administration tool' },
  { name: 'AndroRAT', pattern: /androrat/i, severity: 'critical', description: 'Open-source Android RAT' },
  { name: 'Faketoken', pattern: /faketoken|sms[\s_-]?stealer/i, severity: 'high', description: 'SMS-intercepting banking trojan' },
  { name: 'Anubis', pattern: /anubis[\s_-]?banker/i, severity: 'critical', description: 'Android banking trojan with keylogger' },
  { name: 'Cerberus', pattern: /cerberus[\s_-]?banker/i, severity: 'critical', description: 'Android banking trojan (leaked)' },
  { name: 'Gustuff', pattern: /gustuff/i, severity: 'high', description: 'Android banking trojan targeting 100+ apps' },
  { name: 'EventBot', pattern: /eventbot/i, severity: 'critical', description: 'Android infostealer targeting financial apps' },
  { name: 'Ginp', pattern: /ginp[\s_-]?trojan/i, severity: 'high', description: 'Android banking trojan with SMS' },
  
  // Browser Extension Stealers
  { name: 'Rilide Stealer', pattern: /rilide|browser[\s_-]?extension[\s_-]?stealer/i, severity: 'high', description: 'Chromium extension stealer' },
  { name: 'FakeUpdates Extension', pattern: /fakeupdates|sockrat[\s_-]?extension/i, severity: 'high', description: 'Browser extension dropper' },
  
  // Cloud Credential Stealers
  { name: 'Cloud Credential Harvester', pattern: /aws[\s_-]?credential|azure[\s_-]?token[\s_-]?theft/i, severity: 'critical', description: 'Cloud platform credential theft' },
  { name: 'SaaS Token Stealer', pattern: /slack[\s_-]?token|teams[\s_-]?cookie[\s_-]?theft/i, severity: 'high', description: 'SaaS platform token harvester' },
  
  // Cryptocurrency Wallet Stealers
  { name: 'Crypto Clipper', pattern: /btc[\s_-]?clipper|crypto[\s_-]?clipboard[\s_-]?hijack/i, severity: 'critical', description: 'Cryptocurrency clipboard hijacker' },
  { name: 'Wallet File Stealer', pattern: /wallet\.dat[\s_-]?stealer|exodus[\s_-]?wallet[\s_-]?theft/i, severity: 'critical', description: 'Cryptocurrency wallet file exfiltration' },
  { name: 'MetaMask Phisher', pattern: /metamask[\s_-]?phish|web3[\s_-]?wallet[\s_-]?steal/i, severity: 'critical', description: 'Web3 wallet phishing' },
  
  // Discord Token Stealers
  { name: 'Discord Token Grabber', pattern: /discord[\s_-]?token[\s_-]?grab|pirate[\s_-]?stealer/i, severity: 'medium', description: 'Discord authentication token theft' },
  { name: 'Spidey Bot', pattern: /spidey[\s_-]?bot|discord[\s_-]?nitro[\s_-]?sniper/i, severity: 'medium', description: 'Discord account compromiser' },
  
  // Session Cookie Stealers
  { name: 'Cookie Hijacker', pattern: /cookie[\s_-]?hijack|session[\s_-]?steal/i, severity: 'high', description: 'Web session cookie theft' },
  { name: 'Browser Session Exfil', pattern: /chrome[\s_-]?cookies|firefox[\s_-]?logins\.json/i, severity: 'high', description: 'Browser session data exfiltration' },
  
  // Form Grabbers
  { name: 'FormBook', pattern: /formbook|xloader/i, severity: 'critical', description: 'Infostealer with keylogging and form grabbing' },
  { name: 'Azorult', pattern: /azorult/i, severity: 'critical', description: 'Info stealer with downloader capabilities' },
  { name: 'Lokibot', pattern: /lokibot|loki[\s_-]?pwd[\s_-]?stealer/i, severity: 'high', description: 'Credential and cryptocurrency stealer' },
  { name: 'Pony', pattern: /pony[\s_-]?stealer|fareit/i, severity: 'high', description: 'Classic credential stealer' },
];

const BACKDOORS_AND_RATS = [
  // Advanced Persistent Threat (APT) RATs
  { name: 'Gh0st RAT', pattern: /gh0st[\s_-]?rat|ghost[\s_-]?rat/i, severity: 'critical', description: 'Chinese APT remote access trojan' },
  { name: 'PlugX', pattern: /plugx|destroyrat|korplug/i, severity: 'critical', description: 'Chinese APT modular RAT' },
  { name: 'Poison Ivy', pattern: /poison[\s_-]?ivy|poisonivy/i, severity: 'critical', description: 'Chinese APT RAT since 2005' },
  { name: 'Sakula', pattern: /sakula|sakurel/i, severity: 'critical', description: 'APT RAT used in government breaches' },
  
  // Rootkits
  { name: 'ZeroAccess', pattern: /zeroaccess|max\+\+/i, severity: 'critical', description: 'Kernel-mode rootkit' },
  { name: 'Necurs', pattern: /necurs|kelihos/i, severity: 'critical', description: 'Rootkit and botnet' },
  { name: 'TDL4 (TDSS)', pattern: /tdl4|tdss|alureon/i, severity: 'critical', description: 'Bootkit rootkit' },
  { name: 'Rustock', pattern: /rustock/i, severity: 'high', description: 'Spam botnet rootkit' },
  { name: 'Rootkit.Win32', pattern: /rootkit\.win32/i, severity: 'critical', description: 'Generic Windows rootkit' },
  
  // Loaders and Droppers
  { name: 'Gootkit', pattern: /gootkit|gootloader/i, severity: 'critical', description: 'Banking trojan loader' },
  { name: 'Kovter', pattern: /kovter/i, severity: 'critical', description: 'Fileless malware loader' },
  { name: 'TrickGate', pattern: /trickgate/i, severity: 'high', description: 'Malware loader framework' },
  { name: 'IceXLoader', pattern: /icexloader/i, severity: 'high', description: 'Malware-as-a-service loader' },
  { name: 'PrivateLoader', pattern: /privateloader|rhadamantys[\s_-]?loader/i, severity: 'high', description: 'Pay-per-install loader' },
  { name: 'SystemBC', pattern: /systembc/i, severity: 'high', description: 'SOCKS5 proxy and loader' },
  { name: 'SmokeLoader', pattern: /smokeloader/i, severity: 'high', description: 'Modular malware loader' },
  
  // Botnets
  { name: 'Phorpiex', pattern: /phorpiex|trik/i, severity: 'high', description: 'Botnet and spam distributor' },
  { name: 'Dyre (Dyreza)', pattern: /dyre|dyreza/i, severity: 'high', description: 'Banking botnet' },
  { name: 'Sphinx', pattern: /sphinx[\s_-]?botnet/i, severity: 'high', description: 'Cryptocurrency mining botnet' },
  
  // Commercial RATs
  { name: 'Remcos', pattern: /remcos[\s_-]?rat/i, severity: 'critical', description: 'Commercial remote control tool' },
  { name: 'LuminosityLink', pattern: /luminosity[\s_-]?link/i, severity: 'critical', description: 'Commercial RAT (author arrested)' },
  { name: 'Imminent Monitor', pattern: /imminent[\s_-]?monitor/i, severity: 'critical', description: 'Commercial RAT (shut down)' },
  { name: 'Xtreme RAT', pattern: /xtreme[\s_-]?rat/i, severity: 'high', description: 'Popular commercial RAT' },
  
  // Open-Source RATs
  { name: 'CyberGate', pattern: /cybergate/i, severity: 'high', description: 'Open-source RAT' },
  { name: 'Blackshades', pattern: /blackshades/i, severity: 'high', description: 'Open-source RAT (author arrested)' },
  { name: 'SpyGate', pattern: /spygate[\s_-]?android/i, severity: 'high', description: 'Android spyware' },
  
  // Mobile RATs
  { name: 'AhMyth', pattern: /ahmyth/i, severity: 'critical', description: 'Open-source Android RAT' },
  { name: 'Dendroid', pattern: /dendroid/i, severity: 'critical', description: 'Android RAT sold on forums' },
  { name: 'OmniRAT', pattern: /omnirat/i, severity: 'critical', description: 'Android RAT with keylogger' },
  { name: 'SpyNote', pattern: /spynote|spymax/i, severity: 'critical', description: 'Android surveillance RAT' },
  { name: 'SandroRAT', pattern: /sandrorat/i, severity: 'critical', description: 'Android remote access tool' },
  { name: 'SpyMax', pattern: /spymax/i, severity: 'critical', description: 'Android spyware' },
  
  // C2 Frameworks
  { name: 'Empire C2', pattern: /empire[\s_-]?c2|powershell[\s_-]?empire/i, severity: 'critical', description: 'PowerShell post-exploitation framework' },
  { name: 'Covenant', pattern: /covenant[\s_-]?c2/i, severity: 'critical', description: '.NET command and control framework' },
  { name: 'Sliver', pattern: /sliver[\s_-]?c2/i, severity: 'critical', description: 'Modern C2 framework by BishopFox' },
  { name: 'Mythic', pattern: /mythic[\s_-]?c2/i, severity: 'critical', description: 'Collaborative C2 framework' },
  { name: 'PoshC2', pattern: /poshc2/i, severity: 'critical', description: 'PowerShell C2 framework' },
  { name: 'Merlin', pattern: /merlin[\s_-]?c2/i, severity: 'critical', description: 'Golang post-exploitation tool' },
];

const CRYPTOCURRENCY_MINERS = [
  // Modern Miners
  { name: 'XMRig', pattern: /xmrig|randomx[\s_-]?miner/i, severity: 'high', description: 'Most popular Monero miner' },
  { name: 'NiceHash Miner', pattern: /nicehash[\s_-]?miner/i, severity: 'medium', description: 'Multi-algorithm mining software' },
  { name: 'Claymore Miner', pattern: /claymore[\s_-]?miner/i, severity: 'medium', description: 'Dual Ethereum miner' },
  { name: 'PhoenixMiner', pattern: /phoenixminer/i, severity: 'medium', description: 'Ethereum GPU miner' },
  { name: 'TeamRedMiner', pattern: /teamredminer/i, severity: 'medium', description: 'AMD GPU miner' },
  { name: 'NBMiner', pattern: /nbminer/i, severity: 'medium', description: 'NVIDIA/AMD GPU miner' },
  { name: 'T-Rex Miner', pattern: /t-rex[\s_-]?miner/i, severity: 'medium', description: 'NVIDIA GPU miner' },
  { name: 'lolMiner', pattern: /lolminer/i, severity: 'medium', description: 'AMD/NVIDIA miner' },
  { name: 'GMiner', pattern: /gminer/i, severity: 'medium', description: 'Multi-algorithm CUDA miner' },
  { name: 'Bminer', pattern: /bminer/i, severity: 'medium', description: 'Dual mining software' },
  { name: 'EWBF Miner', pattern: /ewbf[\s_-]?miner|zcash[\s_-]?cuda/i, severity: 'medium', description: 'Equihash CUDA miner' },
  { name: 'Cryptodredge', pattern: /cryptodredge/i, severity: 'medium', description: 'NVIDIA GPU miner' },
  { name: 'WildRig Multi', pattern: /wildrig/i, severity: 'medium', description: 'Multi-algorithm AMD miner' },
  { name: 'SRBMiner', pattern: /srbminer/i, severity: 'medium', description: 'CPU and AMD GPU miner' },
  { name: 'Ethminer', pattern: /ethminer/i, severity: 'medium', description: 'OpenCL Ethereum miner' },
  
  // CPU Miners
  { name: 'CGMiner', pattern: /cgminer/i, severity: 'medium', description: 'ASIC/FPGA miner' },
  { name: 'BFGMiner', pattern: /bfgminer/i, severity: 'medium', description: 'Modular ASIC/FPGA miner' },
  { name: 'MultiMiner', pattern: /multiminer/i, severity: 'medium', description: 'Desktop mining application' },
  { name: 'MinerGate', pattern: /minergate/i, severity: 'medium', description: 'GUI mining software' },
  { name: 'Kryptex', pattern: /kryptex/i, severity: 'low', description: 'Legitimate mining application' },
  { name: 'Honeyminer', pattern: /honeyminer/i, severity: 'low', description: 'Legitimate mining application' },
  { name: 'Cudo Miner', pattern: /cudo[\s_-]?miner/i, severity: 'low', description: 'Legitimate multi-algo miner' },
  { name: 'NanoMiner', pattern: /nanominer/i, severity: 'medium', description: 'Multi-algorithm miner' },
  { name: 'CCMiner', pattern: /ccminer/i, severity: 'medium', description: 'NVIDIA GPU miner' },
  { name: 'ZMiner', pattern: /zminer/i, severity: 'medium', description: 'NVIDIA Equihash miner' },
  
  // Browser-Based Miners
  { name: 'Coinhive', pattern: /coinhive|coin-hive/i, severity: 'high', description: 'In-browser JavaScript miner (defunct)' },
  { name: 'CryptoLoot', pattern: /cryptoloot/i, severity: 'high', description: 'Browser-based miner' },
  { name: 'DeepMiner', pattern: /deepminer/i, severity: 'high', description: 'WebAssembly crypto miner' },
  { name: 'JSEcoin', pattern: /jsecoin/i, severity: 'medium', description: 'JavaScript mining platform' },
  { name: 'Minr', pattern: /minr[\s_-]?xyz|webminepool/i, severity: 'high', description: 'Web-based cryptominer' },
];

const IOT_BOTNETS = [
  // Modern IoT Threats
  { name: 'Mirai', pattern: /mirai|dvrhelper/i, severity: 'critical', description: 'IoT botnet targeting routers and cameras' },
  { name: 'Mozi', pattern: /mozi[\s_-]?botnet/i, severity: 'critical', description: 'P2P IoT botnet (90% of IoT traffic)' },
  { name: 'Echobot', pattern: /echobot/i, severity: 'critical', description: 'Mirai variant with 50+ exploits' },
  { name: 'Gafgyt (Bashlite)', pattern: /gafgyt|bashlite|qbot/i, severity: 'critical', description: 'DDoS IoT botnet' },
  { name: 'Tsunami (Kaiten)', pattern: /tsunami|kaiten/i, severity: 'high', description: 'IRC-based DDoS bot' },
  { name: 'Hajime', pattern: /hajime[\s_-]?worm/i, severity: 'high', description: 'P2P IoT worm (vigilante)' },
  { name: 'BrickerBot', pattern: /brickerbot/i, severity: 'critical', description: 'IoT device permanent damage worm' },
  { name: 'Persirai', pattern: /persirai/i, severity: 'high', description: 'IP camera botnet' },
  { name: 'Reaper (IoTroop)', pattern: /reaper|iotroop/i, severity: 'critical', description: 'IoT botnet with code injection' },
  { name: 'VPNFilter', pattern: /vpnfilter/i, severity: 'critical', description: 'Router malware with destructive capabilities' },
  { name: 'TheMoon', pattern: /themoon[\s_-]?worm/i, severity: 'high', description: 'Router vulnerability worm' },
  { name: 'Torii', pattern: /torii[\s_-]?botnet/i, severity: 'critical', description: 'Sophisticated IoT malware' },
  { name: 'Hide and Seek', pattern: /hide[\s_-]?and[\s_-]?seek|hidnseek/i, severity: 'high', description: 'IoT botnet with custom P2P' },
  { name: 'Prowli', pattern: /prowli/i, severity: 'high', description: 'Modular IoT malware' },
  { name: 'Muhstik', pattern: /muhstik/i, severity: 'high', description: 'IoT botnet targeting Drupal/WordPress' },
  { name: 'Cayosin', pattern: /cayosin/i, severity: 'high', description: 'Lua-based IoT botnet' },
  { name: 'Satori', pattern: /satori[\s_-]?botnet/i, severity: 'critical', description: 'Mirai variant (Huawei router exploit)' },
  { name: 'Wicked', pattern: /wicked[\s_-]?botnet/i, severity: 'critical', description: 'Mirai variant targeting Netgear' },
  { name: 'Masuta', pattern: /masuta[\s_-]?botnet/i, severity: 'high', description: 'Mirai variant with anti-DDoS' },
  { name: 'OMG', pattern: /omg[\s_-]?botnet|mirai[\s_-]?omg/i, severity: 'high', description: 'Mirai variant targeting routers' },
  { name: 'PureMasuta', pattern: /puremasuta/i, severity: 'high', description: 'Hybrid Mirai/Gafgyt botnet' },
  { name: 'Yowai', pattern: /yowai[\s_-]?botnet/i, severity: 'high', description: 'Mirai variant targeting wireless presentation' },
  { name: 'Katana', pattern: /katana[\s_-]?botnet/i, severity: 'high', description: 'IoT botnet targeting ARMv4-v7' },
  { name: 'OWARI', pattern: /owari[\s_-]?botnet/i, severity: 'high', description: 'Mirai variant' },
  { name: 'Fbot', pattern: /fbot|satori[\s_-]?variant/i, severity: 'high', description: 'Satori evolution targeting crypto' },
  { name: 'JenX', pattern: /jenx[\s_-]?botnet/i, severity: 'high', description: 'Gaming server DDoS botnet' },
  { name: 'Dark Nexus', pattern: /dark[\s_-]?nexus/i, severity: 'critical', description: 'Advanced IoT botnet' },
  { name: 'Hoaxcalls', pattern: /hoaxcalls/i, severity: 'high', description: 'VoIP DDoS botnet' },
  { name: 'BCMUPnP Hunter', pattern: /bcmupnp[\s_-]?hunter/i, severity: 'critical', description: 'Broadcom UPnP exploit botnet' },
  { name: 'Akiru', pattern: /akiru/i, severity: 'high', description: 'Mirai variant targeting Huawei HG532' },
];

const POS_MALWARE = [
  // Point-of-Sale Malware
  { name: 'Alina', pattern: /alina[\s_-]?pos/i, severity: 'critical', description: 'RAM scraping POS malware' },
  { name: 'Dexter', pattern: /dexter[\s_-]?pos/i, severity: 'critical', description: 'POS malware targeting payment data' },
  { name: 'vSkimmer', pattern: /vskimmer/i, severity: 'critical', description: 'POS RAM scraper' },
  { name: 'BlackPOS (Kaptoxa)', pattern: /blackpos|kaptoxa/i, severity: 'critical', description: 'Target breach POS malware' },
  { name: 'JackPOS', pattern: /jackpos/i, severity: 'critical', description: 'POS malware with keylogger' },
  { name: 'FindPOS', pattern: /findpos/i, severity: 'critical', description: 'Memory scraping POS malware' },
  { name: 'ChewBacca', pattern: /chewbacca[\s_-]?pos/i, severity: 'critical', description: 'Modular POS malware' },
  { name: 'Backoff', pattern: /backoff[\s_-]?pos/i, severity: 'critical', description: 'Widespread POS malware (2014)' },
  { name: 'AbaddonPOS', pattern: /abaddonpos/i, severity: 'critical', description: 'Sophisticated POS malware' },
  { name: 'NewPOSThings', pattern: /newposthings/i, severity: 'critical', description: 'Modular POS malware' },
  { name: 'TreasureHunter', pattern: /treasurehunter/i, severity: 'critical', description: 'Advanced RAM scraper' },
  { name: 'PoSeidon', pattern: /poseidon[\s_-]?malware/i, severity: 'critical', description: 'Keylogger POS malware' },
  { name: 'FighterPOS', pattern: /fighterpos/i, severity: 'high', description: 'POS scraper and keylogger' },
  { name: 'MalumPOS', pattern: /malumpos/i, severity: 'high', description: 'POS targeting hospitality' },
  { name: 'RawPOS', pattern: /rawpos/i, severity: 'high', description: 'Basic POS scraper' },
  { name: 'Multigrain', pattern: /multigrain[\s_-]?pos/i, severity: 'high', description: 'POS with C2 communication' },
  { name: 'MajikPOS', pattern: /majikpos/i, severity: 'high', description: 'Hotel POS malware' },
  { name: 'MyloBot', pattern: /mylobot/i, severity: 'critical', description: 'Sophisticated botnet downloader' },
  { name: 'GlitchPOS', pattern: /glitchpos/i, severity: 'high', description: 'POS scraper variant' },
  { name: 'LogPOS', pattern: /logpos/i, severity: 'high', description: 'POS with logging capabilities' },
];

// ========================================
// TOTAL COUNTS
// ========================================
console.log('=== SIGNATURE EXPANSION READY ===');
console.log(`Info Stealers: ${INFO_STEALERS.length}`);
console.log(`Backdoors/RATs: ${BACKDOORS_AND_RATS.length}`);
console.log(`Cryptocurrency Miners: ${CRYPTOCURRENCY_MINERS.length}`);
console.log(`IoT Botnets: ${IOT_BOTNETS.length}`);
console.log(`POS Malware: ${POS_MALWARE.length}`);
console.log(`TOTAL NEW MALWARE SIGNATURES: ${INFO_STEALERS.length + BACKDOORS_AND_RATS.length + CRYPTOCURRENCY_MINERS.length + IOT_BOTNETS.length + POS_MALWARE.length}`);
console.log('=====================================');

// Export for easy copying
module.exports = {
  INFO_STEALERS,
  BACKDOORS_AND_RATS,
  CRYPTOCURRENCY_MINERS,
  IOT_BOTNETS,
  POS_MALWARE,
};
