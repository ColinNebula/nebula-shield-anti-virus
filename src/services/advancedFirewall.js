/**
 * Advanced Firewall Engine
 * Deep Packet Inspection, IPS, Application-Level Firewall, Geo-Blocking
 */

// ==================== THREAT INTELLIGENCE ====================

export const THREAT_DATABASE = {
  // Known exploit kits
  exploitKits: [
    { name: 'RIG Exploit Kit', signature: /\/[a-z]{8}\.php\?[a-z]{4}=/, severity: 'critical' },
    { name: 'Magnitude Exploit Kit', signature: /\/gate\.php/, severity: 'critical' },
    { name: 'Fallout Exploit Kit', signature: /\/main\.php\?page=/, severity: 'critical' }
  ],

  // Command & Control patterns
  c2Patterns: [
    { pattern: /^(POST|GET).*\/c2\/beacon/, description: 'Cobalt Strike beacon', severity: 'critical' },
    { pattern: /\/gate\.php/, description: 'Generic C2 gate', severity: 'critical' },
    { pattern: /\/checkip\.php/, description: 'IP check (possible C2)', severity: 'high' }
  ],

  // Malware families
  malwareFamilies: [
    { name: 'Emotet', ports: [8080, 443, 7080], userAgents: ['Wget', 'curl'], severity: 'critical' },
    { name: 'TrickBot', ports: [449, 451, 8082], dnsSuffixes: ['.pw', '.top'], severity: 'critical' },
    { name: 'Dridex', ports: [443, 8443], sniPatterns: ['invoice', 'statement'], severity: 'critical' },
    { name: 'Zeus', ports: [8080, 9090], pathPatterns: ['/gate.php', '/panel/'], severity: 'high' }
  ],

  // Exploit signatures (EXPANDED - 50 signatures)
  exploitSignatures: [
    // ===== Web Application Attacks (10) =====
    { name: 'SQL Injection', pattern: /(union.*select|select.*from|insert.*into|delete.*from|drop.*table|exec.*sp_|xp_cmdshell)/i, severity: 'high' },
    { name: 'XSS Attack', pattern: /<script.*?>|javascript:|onerror=|onload=|eval\(|<iframe/i, severity: 'medium' },
    { name: 'Command Injection', pattern: /(;|\||&&)\s*(rm|cat|ls|wget|curl|nc|bash|powershell|cmd\.exe)/i, severity: 'critical' },
    { name: 'Path Traversal', pattern: /\.\.[\/\\]|\.\.%2f|\.\.%5c/gi, severity: 'high' },
    { name: 'LDAP Injection', pattern: /(\(|\)|\*|\||&).*?(cn=|uid=|ou=)/gi, severity: 'medium' },
    { name: 'XML External Entity (XXE)', pattern: /<!ENTITY.*SYSTEM|<!DOCTYPE.*ENTITY/i, severity: 'high' },
    { name: 'Server-Side Request Forgery (SSRF)', pattern: /(http:\/\/localhost|http:\/\/127\.0\.0\.1|http:\/\/0\.0\.0\.0|file:\/\/|gopher:\/\/)/i, severity: 'high' },
    { name: 'Remote File Inclusion (RFI)', pattern: /include.*?(http:\/\/|https:\/\/|ftp:\/\/)/i, severity: 'critical' },
    { name: 'Local File Inclusion (LFI)', pattern: /include.*?(\/etc\/passwd|\/proc\/self|\.\.\/|\.\.\\)/i, severity: 'high' },
    { name: 'PHP Code Injection', pattern: /(eval\(|assert\(|preg_replace.*\/e|create_function|call_user_func|system\(|passthru\(|shell_exec)/i, severity: 'critical' },

    // ===== Cryptocurrency & Mining (5) =====
    { name: 'Cryptocurrency Mining (Stratum)', pattern: /stratum\+tcp:\/\/|stratum\+ssl:\/\//i, severity: 'high' },
    { name: 'Cryptocurrency Mining (Pool)', pattern: /(mining\.pool|pool\.mining|xmr-stak|claymore|phoenixminer|t-rex|nbminer)/i, severity: 'high' },
    { name: 'Monero Mining', pattern: /(monero|xmr|cryptonight|randomx).*?(pool|miner)/i, severity: 'high' },
    { name: 'Coinhive/CryptoJacking', pattern: /(coinhive|coin-hive|cryptoloot|crypto-loot|jsecoin|minero\.cc)/i, severity: 'critical' },
    { name: 'Mining Configuration', pattern: /(wallet|algo|pool_address|pool_password).*?:.*?(monero|xmr|eth|btc)/i, severity: 'medium' },

    // ===== DNS & Network Attacks (5) =====
    { name: 'DNS Tunneling (Long Subdomain)', pattern: /^[A-Za-z0-9]{50,}\./i, severity: 'high' },
    { name: 'DNS Tunneling (Base64)', pattern: /^[A-Za-z0-9+/=]{40,}\./i, severity: 'high' },
    { name: 'DNS Amplification Attack', pattern: /query.*?ANY.*?RRSIG/i, severity: 'high' },
    { name: 'DGA Domain (Domain Generation Algorithm)', pattern: /^[a-z]{8,20}\.(com|net|org|info|biz)$/i, severity: 'high' },
    { name: 'Fast Flux Network', pattern: /TTL=[0-9]{1,3}.*?A=([0-9]{1,3}\.){3}[0-9]{1,3}/i, severity: 'medium' },

    // ===== Botnet & C2 (7) =====
    { name: 'IRC Bot Commands', pattern: /^(NICK|USER|JOIN|PRIVMSG|MODE|TOPIC).*?(bot|cmd|exec)/i, severity: 'critical' },
    { name: 'HTTP Botnet Beacon', pattern: /\/(bot|cmd|task|command|beacon|check)\/(get|post|update|status)/i, severity: 'critical' },
    { name: 'Botnet Registration', pattern: /\/(bot|client)\/(register|signup|new|install)/i, severity: 'critical' },
    { name: 'Cobalt Strike Beacon', pattern: /(\/activity|\/submit\.php|\/ca|\/dpixel|\/pixel|\/match)/i, severity: 'critical' },
    { name: 'Metasploit Payload', pattern: /(\/INITM|\/INIT.*?JM|meterpreter|\/admin\/get\.php)/i, severity: 'critical' },
    { name: 'Empire C2', pattern: /(\/admin\/get\.php|\/news\.php|\/login\/process\.php).*?session=/i, severity: 'critical' },
    { name: 'Covenant C2', pattern: /(\/api\/tasks|\/api\/taskings|grunthttp)/i, severity: 'critical' },

    // ===== Data Exfiltration (5) =====
    { name: 'Large Data Exfiltration', pattern: /\/upload\/.*?size=[0-9]{8,}/i, severity: 'high' },
    { name: 'Base64 Data Exfiltration', pattern: /(POST|PUT).*?data=[A-Za-z0-9+/=]{500,}/i, severity: 'high' },
    { name: 'FTP Data Exfiltration', pattern: /STOR.*?\.(zip|rar|7z|tar\.gz|db|sql|csv)/i, severity: 'medium' },
    { name: 'Cloud Storage Exfiltration', pattern: /(amazonaws\.com|dropbox\.com|drive\.google\.com|onedrive\.com)\/upload/i, severity: 'medium' },
    { name: 'Email Data Exfiltration', pattern: /(MAIL FROM:|RCPT TO:).*?attachment.*?\.(zip|rar|7z|db)/i, severity: 'medium' },

    // ===== Web Shells & Backdoors (6) =====
    { name: 'PHP Web Shell', pattern: /(c99|r57|b374k|wso|shell|webshell)\.php/i, severity: 'critical' },
    { name: 'ASP.NET Web Shell', pattern: /(aspxspy|awen asp|china chopper)\.aspx/i, severity: 'critical' },
    { name: 'JSP Web Shell', pattern: /(jspspy|customize|shell)\.jsp/i, severity: 'critical' },
    { name: 'Web Shell Commands', pattern: /\?(cmd|exec|command|shell)=|&(cmd|exec|command)=/i, severity: 'critical' },
    { name: 'Encoded Web Shell', pattern: /(eval|base64_decode|gzinflate|str_rot13|assert)\(.*?base64/i, severity: 'critical' },
    { name: 'One-liner Web Shell', pattern: /(system|passthru|shell_exec|exec|popen|proc_open)\(\$_(GET|POST|REQUEST|COOKIE)/i, severity: 'critical' },

    // ===== Exploit Kits & Vulnerabilities (7) =====
    { name: 'Shellshock Exploit', pattern: /\(\)\s*\{\s*:;\s*\};/i, severity: 'critical' },
    { name: 'Log4Shell (Log4j RCE)', pattern: /\$\{jndi:(ldap|rmi|dns|nis|iiop|corba|nds):\/\//i, severity: 'critical' },
    { name: 'Spring4Shell Exploit', pattern: /class\.module\.classLoader\.resources\.context\.parent/i, severity: 'critical' },
    { name: 'ProxyShell Exploit', pattern: /\/autodiscover\/autodiscover\.json.*?@.*?\/mapi\/nspi/i, severity: 'critical' },
    { name: 'ProxyLogon Exploit', pattern: /\/owa\/auth\/.*?@.*?\/ECP/i, severity: 'critical' },
    { name: 'Eternal Blue (MS17-010)', pattern: /SMBv1.*?FEA.*?NTLMv1/i, severity: 'critical' },
    { name: 'BlueKeep (RDP RCE)', pattern: /MS_T120.*?RDP/i, severity: 'critical' },

    // ===== Reconnaissance & Scanning (5) =====
    { name: 'Nmap Scan', pattern: /Nmap.*?scan|User-Agent:.*?Nmap/i, severity: 'medium' },
    { name: 'Masscan Scan', pattern: /User-Agent:.*?masscan/i, severity: 'medium' },
    { name: 'Nikto Scan', pattern: /User-Agent:.*?nikto/i, severity: 'medium' },
    { name: 'SQLMap Scan', pattern: /User-Agent:.*?sqlmap|sqlmap\/[0-9]/i, severity: 'high' },
    { name: 'Directory Bruteforce', pattern: /(dirbuster|dirb|gobuster|wfuzz).*?\/.*?\/(admin|backup|config|db|sql)/i, severity: 'medium' }
  ],

  // Ransomware indicators (EXPANDED - 15+ families)
  ransomwareIndicators: [
    // File extensions used by ransomware
    { extension: /\.(locked|encrypted|crypted|cerber|locky|wannacry|zepto|sage|spora|jaff|magniber|gandcrab|ryuk|revil|sodinokibi|conti|lockbit|blackmatter|darkside|maze|egregor|netwalker|dharma|phobos|makop|snatch)$/i, severity: 'critical' },
    
    // Process names of known ransomware
    { processName: /^(wcry|wannacry|cerber|locky|cryptolocker|teslacrypt|cryptowall|petya|notpetya|badrabbit|ryuk|revil|sodinokibi|darkside|blackmatter|conti|lockbit|maze|ragnarok|egregor|netwalker|avaddon|babuk|clop|hive|alpha|blackcat|royal)\.exe$/i, severity: 'critical' },
    
    // Network patterns (C2, payment, TOR)
    { networkPattern: /\/(payment|pay|decrypt|unlock|recover)\/(bitcoin|btc|ransom|key)/i, severity: 'critical' },
    { networkPattern: /\/files\/(readme|decrypt|instructions|how_to_decrypt|restore_files)\.(txt|html)/i, severity: 'critical' },
    { networkPattern: /onion\.(to|link|ly|cab|direct)\/[a-z0-9]{16}/i, severity: 'critical' },
    
    // Ransom note patterns
    { filePattern: /^(readme|decrypt|instructions|how_to_decrypt|restore_files|recovery|your_files|files_encrypted)\.(txt|html)$/i, severity: 'critical' },
    { filePattern: /^[A-Z0-9]{8}-readme\.txt$/i, severity: 'critical' },
    
    // Bitcoin wallet patterns
    { bitcoinWallet: /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/i, severity: 'high' },
    
    // Suspicious mass file operations
    { behavior: 'mass_encryption', pattern: /encrypted.*?\.(doc|xls|pdf|jpg|png).*?in.*?[0-9]+.*?seconds/i, severity: 'critical' }
  ],

  // ===== Phishing & Social Engineering (5) =====
  phishingIndicators: [
    { name: 'Typosquatting Domain', pattern: /(paypa1|amaz0n|micros0ft|g00gle|faceb00k|app1e|netf1ix)/i, severity: 'high' },
    { name: 'Brand Impersonation', pattern: /(paypal|amazon|microsoft|google|facebook|apple|netflix)-[a-z0-9]+\.(com|net|org)/i, severity: 'high' },
    { name: 'Suspicious TLD', pattern: /\.(tk|ml|ga|cf|gq|pw|top|work|click|link|zip)$/i, severity: 'medium' },
    { name: 'Unicode Homograph Attack', pattern: /[а-яА-Я]|[α-ωΑ-Ω]|[\u0400-\u04FF]|[\u0370-\u03FF]/i, severity: 'high' },
    { name: 'Credential Harvesting Form', pattern: /(login|signin|password|username).*?(verify|confirm|update|suspend|alert)/i, severity: 'medium' }
  ],

  // ===== Tor & Anonymization (5) =====
  anonymizationIndicators: [
    { name: 'Tor Onion Address', pattern: /[a-z2-7]{16,56}\.onion/i, severity: 'medium' },
    { name: 'Tor Bridge Connection', pattern: /bridge.*?obfs[34]|meek/i, severity: 'medium' },
    { name: 'VPN Protocol (OpenVPN)', pattern: /P_CONTROL_HARD_RESET|P_ACK_V1/i, severity: 'low' },
    { name: 'VPN Protocol (WireGuard)', pattern: /wg0|wireguard/i, severity: 'low' },
    { name: 'SOCKS Proxy', pattern: /CONNECT.*?:(1080|9050|9150)/i, severity: 'medium' }
  ],

  // ===== Malicious File Patterns (5) =====
  maliciousFilePatterns: [
    { name: 'Double Extension', pattern: /\.(pdf|doc|xls|jpg|png)\.(exe|scr|bat|cmd|vbs|js)$/i, severity: 'critical' },
    { name: 'Suspicious Executable Extension', pattern: /\.(scr|pif|application|gadget|msi|msp|com|bat|cmd|vb|vbs|vbe|js|jse|ws|wsf|wsc|wsh|ps1|ps1xml|ps2|ps2xml|psc1|psc2|msh|msh1|msh2|mshxml|msh1xml|msh2xml)$/i, severity: 'high' },
    { name: 'Macro-Enabled Office File', pattern: /\.(docm|xlsm|pptm|dotm|xltm|potm)$/i, severity: 'medium' },
    { name: 'Archive Bomb', pattern: /\.(zip|rar|7z|gz|bz2).*?size=([0-9]{9,})/i, severity: 'high' },
    { name: 'Suspicious Archive Content', pattern: /\.(zip|rar|7z).*?contains.*?\.(exe|scr|bat|vbs)/i, severity: 'high' }
  ],

  // ===== Suspicious User Agents (5) =====
  suspiciousUserAgents: [
    { name: 'Hacking Tools', pattern: /^(curl|wget|python-requests|go-http-client|ruby|perl|jakarta|apache-httpclient)\/[0-9]/i, severity: 'medium' },
    { name: 'Vulnerability Scanners', pattern: /(masscan|nmap|nikto|sqlmap|metasploit|burpsuite|acunetix|nessus|openvas|qualys|rapid7)/i, severity: 'high' },
    { name: 'Bots & Crawlers', pattern: /(bot|crawler|spider|scraper|harvest).*?\/(scan|search|collect)/i, severity: 'low' },
    { name: 'Suspicious Empty User-Agent', pattern: /^User-Agent:\s*$/i, severity: 'medium' },
    { name: 'Old/Rare Browsers', pattern: /(MSIE [1-6]\.|Netscape\/[1-4]|Opera\/[1-7])/i, severity: 'low' }
  ],

  // ===== Password & Authentication Attacks (5) =====
  authenticationAttacks: [
    { name: 'Brute Force Attack', pattern: /failed.*?login.*?attempts?.*?([5-9]|[1-9][0-9]+)/i, severity: 'high' },
    { name: 'Credential Stuffing', pattern: /POST.*?\/login.*?username=.*?&password=.*?\|/i, severity: 'high' },
    { name: 'Password Spraying', pattern: /multiple.*?usernames.*?same.*?password/i, severity: 'high' },
    { name: 'Session Hijacking', pattern: /Cookie:.*?PHPSESSID=[a-f0-9]{32}.*?X-Forwarded-For:/i, severity: 'high' },
    { name: 'JWT Token Manipulation', pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.(none|HS256)/i, severity: 'medium' }
  ]
};

// ==================== GEO IP DATABASE (Enhanced) ====================

export const GEO_IP_DATABASE = {
  // High-risk countries (often blocked in corporate environments)
  highRiskCountries: ['KP', 'IR', 'SY', 'CU', 'SD', 'BY'],
  
  // Country codes to names
  countries: {
    'US': { name: 'United States', flag: '🇺🇸', risk: 'low' },
    'GB': { name: 'United Kingdom', flag: '🇬🇧', risk: 'low' },
    'CA': { name: 'Canada', flag: '🇨🇦', risk: 'low' },
    'DE': { name: 'Germany', flag: '🇩🇪', risk: 'low' },
    'FR': { name: 'France', flag: '🇫🇷', risk: 'low' },
    'JP': { name: 'Japan', flag: '🇯🇵', risk: 'low' },
    'AU': { name: 'Australia', flag: '🇦🇺', risk: 'low' },
    'CN': { name: 'China', flag: '🇨🇳', risk: 'medium' },
    'RU': { name: 'Russia', flag: '🇷🇺', risk: 'medium' },
    'KP': { name: 'North Korea', flag: '🇰🇵', risk: 'critical' },
    'IR': { name: 'Iran', flag: '🇮🇷', risk: 'high' },
    'SY': { name: 'Syria', flag: '🇸🇾', risk: 'high' },
    'CU': { name: 'Cuba', flag: '🇨🇺', risk: 'high' },
    'SD': { name: 'Sudan', flag: '🇸🇩', risk: 'high' },
    'BY': { name: 'Belarus', flag: '🇧🇾', risk: 'high' },
    'BR': { name: 'Brazil', flag: '🇧🇷', risk: 'medium' },
    'IN': { name: 'India', flag: '🇮🇳', risk: 'low' },
    'NL': { name: 'Netherlands', flag: '🇳🇱', risk: 'low' },
    'SG': { name: 'Singapore', flag: '🇸🇬', risk: 'low' },
    'IT': { name: 'Italy', flag: '🇮🇹', risk: 'low' },
    'ES': { name: 'Spain', flag: '🇪🇸', risk: 'low' },
    'MX': { name: 'Mexico', flag: '🇲🇽', risk: 'medium' },
    'KR': { name: 'South Korea', flag: '🇰🇷', risk: 'low' },
    'SE': { name: 'Sweden', flag: '🇸🇪', risk: 'low' },
    'NO': { name: 'Norway', flag: '🇳🇴', risk: 'low' },
    'PL': { name: 'Poland', flag: '🇵🇱', risk: 'low' },
    'UA': { name: 'Ukraine', flag: '🇺🇦', risk: 'medium' },
    'VN': { name: 'Vietnam', flag: '🇻🇳', risk: 'medium' },
    'ID': { name: 'Indonesia', flag: '🇮🇩', risk: 'medium' },
    'PK': { name: 'Pakistan', flag: '🇵🇰', risk: 'medium' }
  },

  // ASN to organization mapping
  asn: {
    '15169': { org: 'Google LLC', reputation: 'trusted' },
    '13335': { org: 'Cloudflare', reputation: 'trusted' },
    '8075': { org: 'Microsoft Corporation', reputation: 'trusted' },
    '16509': { org: 'Amazon AWS', reputation: 'trusted' },
    '32934': { org: 'Facebook', reputation: 'trusted' },
    '396982': { org: 'Google Cloud', reputation: 'trusted' }
  }
};

// ==================== DEEP PACKET INSPECTION ====================

export class DeepPacketInspector {
  constructor() {
    this.inspectionRules = [];
    this.packetCache = new Map();
    this.anomalyThreshold = 0.7;
  }

  /**
   * Inspect packet payload for threats
   */
  inspectPacket(packet) {
    const threats = [];

    // Check for exploit signatures
    for (const exploit of THREAT_DATABASE.exploitSignatures) {
      if (exploit.pattern.test(packet.payload)) {
        threats.push({
          type: 'exploit',
          name: exploit.name,
          severity: exploit.severity,
          pattern: exploit.pattern.toString(),
          action: 'block'
        });
      }
    }

    // Check for C2 communication
    for (const c2 of THREAT_DATABASE.c2Patterns) {
      if (c2.pattern.test(packet.payload)) {
        threats.push({
          type: 'c2_communication',
          description: c2.description,
          severity: c2.severity,
          action: 'block_and_alert'
        });
      }
    }

    // Check for malware family indicators
    for (const malware of THREAT_DATABASE.malwareFamilies) {
      if (malware.ports.includes(packet.destPort)) {
        if (malware.userAgents && packet.userAgent) {
          if (malware.userAgents.some(ua => packet.userAgent.includes(ua))) {
            threats.push({
              type: 'malware_family',
              name: malware.name,
              severity: malware.severity,
              indicator: 'port_and_useragent',
              action: 'block_and_quarantine'
            });
          }
        }
      }
    }

    // Protocol anomaly detection
    const anomalies = this.detectAnomalies(packet);
    if (anomalies.length > 0) {
      threats.push(...anomalies);
    }

    return {
      threats,
      clean: threats.length === 0,
      action: this.determineAction(threats)
    };
  }

  /**
   * Detect protocol anomalies
   */
  detectAnomalies(packet) {
    const anomalies = [];

    // Check HTTP anomalies
    if (packet.protocol === 'HTTP') {
      // Suspicious HTTP methods
      if (['TRACE', 'TRACK', 'DEBUG'].includes(packet.method)) {
        anomalies.push({
          type: 'protocol_anomaly',
          description: `Suspicious HTTP method: ${packet.method}`,
          severity: 'medium',
          action: 'log'
        });
      }

      // Excessively long headers
      if (packet.headers && JSON.stringify(packet.headers).length > 8192) {
        anomalies.push({
          type: 'protocol_anomaly',
          description: 'Excessively long HTTP headers (possible buffer overflow)',
          severity: 'high',
          action: 'block'
        });
      }

      // Multiple Host headers (HTTP smuggling)
      if (packet.headers && packet.headers.filter(h => h.name === 'Host').length > 1) {
        anomalies.push({
          type: 'http_smuggling',
          description: 'Multiple Host headers detected',
          severity: 'high',
          action: 'block'
        });
      }
    }

    // Check DNS anomalies
    if (packet.protocol === 'DNS') {
      // DNS tunneling detection (excessive queries)
      const dnsQueryRate = this.getDNSQueryRate(packet.sourceIP);
      if (dnsQueryRate > 100) { // More than 100 queries per minute
        anomalies.push({
          type: 'dns_tunneling',
          description: 'Abnormal DNS query rate (possible data exfiltration)',
          severity: 'high',
          rate: dnsQueryRate,
          action: 'throttle_and_alert'
        });
      }

      // Suspicious TLD
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc'];
      if (suspiciousTLDs.some(tld => packet.domain && packet.domain.endsWith(tld))) {
        anomalies.push({
          type: 'suspicious_domain',
          description: 'Query to suspicious TLD',
          severity: 'medium',
          domain: packet.domain,
          action: 'log'
        });
      }
    }

    // TCP anomalies
    if (packet.protocol === 'TCP') {
      // SYN flood detection
      if (packet.flags === 'SYN' && this.getSYNRate(packet.sourceIP) > 50) {
        anomalies.push({
          type: 'syn_flood',
          description: 'Possible SYN flood attack',
          severity: 'high',
          action: 'rate_limit'
        });
      }

      // Port scanning detection
      const uniquePorts = this.getUniquePortsScanned(packet.sourceIP);
      if (uniquePorts > 20) {
        anomalies.push({
          type: 'port_scan',
          description: 'Port scanning activity detected',
          severity: 'medium',
          ports: uniquePorts,
          action: 'block_and_log'
        });
      }
    }

    return anomalies;
  }

  /**
   * Determine action based on threats
   */
  determineAction(threats) {
    if (threats.length === 0) return 'allow';

    const hasCritical = threats.some(t => t.severity === 'critical');
    const hasHigh = threats.some(t => t.severity === 'high');

    if (hasCritical) return 'block_and_alert';
    if (hasHigh) return 'block';
    return 'log';
  }

  // Helper methods (would use real state in production)
  getDNSQueryRate(ip) { return Math.floor(Math.random() * 150); }
  getSYNRate(ip) { return Math.floor(Math.random() * 100); }
  getUniquePortsScanned(ip) { return Math.floor(Math.random() * 30); }
}

// ==================== INTRUSION PREVENTION SYSTEM ====================

export class IntrusionPreventionSystem {
  constructor() {
    this.signatures = this.loadSignatures();
    this.behaviorModels = new Map();
    this.alertThreshold = 3;
    this.blockDuration = 3600000; // 1 hour in ms
  }

  /**
   * Load IPS signatures
   */
  loadSignatures() {
    return [
      // Network-based signatures
      {
        id: 'IPS-001',
        name: 'Brute Force SSH',
        pattern: /ssh.*failed.*password/i,
        threshold: 5,
        window: 300000, // 5 minutes
        severity: 'high',
        action: 'block_ip'
      },
      {
        id: 'IPS-002',
        name: 'SQL Injection Attempt',
        pattern: /(union.*select|;.*drop|exec.*xp_)/i,
        threshold: 1,
        window: 0,
        severity: 'high',
        action: 'block_and_log'
      },
      {
        id: 'IPS-003',
        name: 'Web Shell Upload',
        pattern: /(eval\(|base64_decode|system\(|passthru)/i,
        threshold: 1,
        window: 0,
        severity: 'critical',
        action: 'block_ip'
      },
      {
        id: 'IPS-004',
        name: 'Directory Traversal',
        pattern: /\.\.[\/\\]/,
        threshold: 3,
        window: 60000,
        severity: 'medium',
        action: 'block_session'
      },
      {
        id: 'IPS-005',
        name: 'Shellshock Exploit',
        pattern: /\(\)\s*\{\s*[:;]\s*\}\s*;/,
        threshold: 1,
        window: 0,
        severity: 'critical',
        action: 'block_ip'
      }
    ];
  }

  /**
   * Analyze traffic for intrusion attempts
   */
  analyzeTraffic(connection) {
    const alerts = [];

    // Signature-based detection
    for (const signature of this.signatures) {
      if (this.matchSignature(connection, signature)) {
        alerts.push({
          id: signature.id,
          name: signature.name,
          severity: signature.severity,
          action: signature.action,
          timestamp: new Date().toISOString(),
          sourceIP: connection.remoteAddress,
          details: this.getSignatureDetails(connection, signature)
        });
      }
    }

    // Behavior-based detection
    const behaviorAlerts = this.detectAnomalousBehavior(connection);
    alerts.push(...behaviorAlerts);

    // Determine response
    if (alerts.length > 0) {
      return {
        blocked: alerts.some(a => a.action.includes('block')),
        alerts,
        action: this.determineResponseAction(alerts),
        recommendation: this.getRecommendation(alerts)
      };
    }

    return { blocked: false, alerts: [], action: 'allow' };
  }

  /**
   * Match connection against signature
   */
  matchSignature(connection, signature) {
    const payload = connection.payload || '';
    const url = connection.url || '';
    const combined = payload + url;

    return signature.pattern.test(combined);
  }

  /**
   * Detect anomalous behavior
   */
  detectAnomalousBehavior(connection) {
    const alerts = [];
    const sourceIP = connection.remoteAddress;

    // Get or create behavior profile
    if (!this.behaviorModels.has(sourceIP)) {
      this.behaviorModels.set(sourceIP, {
        firstSeen: Date.now(),
        requestCount: 0,
        uniquePorts: new Set(),
        failedAttempts: 0,
        dataTransferred: 0
      });
    }

    const profile = this.behaviorModels.get(sourceIP);
    profile.requestCount++;
    profile.uniquePorts.add(connection.remotePort);
    profile.dataTransferred += (connection.bandwidth?.sent || 0) + (connection.bandwidth?.received || 0);

    // Rapid connection attempts
    const timeSinceFirst = Date.now() - profile.firstSeen;
    const requestRate = profile.requestCount / (timeSinceFirst / 1000);
    if (requestRate > 10) { // More than 10 requests per second
      alerts.push({
        id: 'BEH-001',
        name: 'Rapid Connection Attempts',
        severity: 'medium',
        action: 'rate_limit',
        details: { rate: requestRate.toFixed(2), requests: profile.requestCount }
      });
    }

    // Port scanning behavior
    if (profile.uniquePorts.size > 20) {
      alerts.push({
        id: 'BEH-002',
        name: 'Port Scanning Detected',
        severity: 'high',
        action: 'block_ip',
        details: { ports: profile.uniquePorts.size }
      });
    }

    // Excessive data transfer
    if (profile.dataTransferred > 100 * 1024 * 1024) { // 100MB
      alerts.push({
        id: 'BEH-003',
        name: 'Excessive Data Transfer',
        severity: 'medium',
        action: 'throttle',
        details: { bytes: profile.dataTransferred }
      });
    }

    return alerts;
  }

  /**
   * Determine response action
   */
  determineResponseAction(alerts) {
    const criticalCount = alerts.filter(a => a.severity === 'critical').length;
    const highCount = alerts.filter(a => a.severity === 'high').length;

    if (criticalCount > 0) return 'block_ip_permanent';
    if (highCount >= 2) return 'block_ip_temporary';
    if (alerts.length >= this.alertThreshold) return 'rate_limit';
    return 'log';
  }

  /**
   * Get recommendation
   */
  getRecommendation(alerts) {
    const critical = alerts.filter(a => a.severity === 'critical');
    if (critical.length > 0) {
      return `Critical threat detected (${critical[0].name}). IP has been permanently blocked. Review logs immediately.`;
    }

    const high = alerts.filter(a => a.severity === 'high');
    if (high.length > 0) {
      return `High-severity intrusion attempt detected. Consider blocking this IP range.`;
    }

    return 'Suspicious activity logged. Monitor for patterns.';
  }

  getSignatureDetails(connection, signature) {
    return {
      matchedPattern: signature.pattern.toString(),
      payload: (connection.payload || '').substring(0, 100) + '...',
      timestamp: new Date().toISOString()
    };
  }
}

// ==================== APPLICATION-LEVEL FIREWALL ====================

export class ApplicationFirewall {
  constructor() {
    this.appRules = new Map();
    this.trustedApps = new Set([
      'chrome.exe',
      'firefox.exe',
      'msedge.exe',
      'outlook.exe',
      'teams.exe',
      'slack.exe',
      'discord.exe'
    ]);
    this.blockedApps = new Set();
  }

  normalizeProcessName(processName) {
    if (!processName || typeof processName !== 'string') return '';
    const trimmed = processName.trim();
    if (!trimmed) return '';
    const normalized = trimmed.replace(/\\/g, '/');
    const parts = normalized.split('/');
    return (parts[parts.length - 1] || '').toLowerCase();
  }

  normalizeDestination(destination) {
    if (!destination || typeof destination !== 'string') return '';
    return destination.trim().toLowerCase();
  }

  matchDestination(destination, ruleDest) {
    if (!ruleDest) return false;
    const dest = this.normalizeDestination(destination);

    if (ruleDest instanceof RegExp) {
      return ruleDest.test(dest);
    }

    if (typeof ruleDest === 'string') {
      const trimmed = ruleDest.trim();
      if (!trimmed) return false;
      if (trimmed.startsWith('/') && trimmed.endsWith('/') && trimmed.length > 2) {
        try {
          const pattern = trimmed.slice(1, -1);
          return new RegExp(pattern, 'i').test(dest);
        } catch (error) {
          return false;
        }
      }
      return dest.includes(trimmed.toLowerCase());
    }

    return false;
  }

  /**
   * Check if application is allowed to access network
   */
  checkApplicationAccess(processName, destination) {
    const normalizedName = this.normalizeProcessName(processName);
    if (!normalizedName) {
      return {
        allowed: false,
        reason: 'Missing or invalid process name',
        action: 'prompt',
        promptRequired: true
      };
    }

    // Blocked apps
    if (this.blockedApps.has(normalizedName)) {
      return {
        allowed: false,
        reason: 'Application is blacklisted',
        action: 'block'
      };
    }

    // Trusted apps
    if (this.trustedApps.has(normalizedName)) {
      return {
        allowed: true,
        reason: 'Trusted application',
        action: 'allow'
      };
    }

    // Check custom rules
    const rule = this.appRules.get(normalizedName);
    if (rule) {
      return this.evaluateAppRule(rule, destination);
    }

    // Unknown app - prompt user (in real implementation)
    return {
      allowed: false,
      reason: 'Unknown application - user approval required',
      action: 'prompt',
      promptRequired: true
    };
  }

  /**
   * Add application rule
   */
  addApplicationRule(processName, rule) {
    const normalizedName = this.normalizeProcessName(processName);
    if (!normalizedName) return;

    const normalizedRule = {
      action: rule && rule.action ? rule.action : 'allow',
      allowedDestinations: (rule && rule.allowedDestinations) || [],
      blockedDestinations: (rule && rule.blockedDestinations) || [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.appRules.set(normalizedName, normalizedRule);
  }

  /**
   * Block application
   */
  blockApplication(processName) {
    const normalizedName = this.normalizeProcessName(processName);
    if (!normalizedName) return;
    this.blockedApps.add(normalizedName);
    this.trustedApps.delete(normalizedName);
  }

  /**
   * Trust application
   */
  trustApplication(processName) {
    const normalizedName = this.normalizeProcessName(processName);
    if (!normalizedName) return;
    this.trustedApps.add(normalizedName);
    this.blockedApps.delete(normalizedName);
  }

  /**
   * Evaluate application rule
   */
  evaluateAppRule(rule, destination) {
    const dest = this.normalizeDestination(destination);

    if (rule.blockedDestinations && rule.blockedDestinations.length > 0) {
      const blocked = rule.blockedDestinations.some(ruleDest =>
        this.matchDestination(dest, ruleDest)
      );

      if (blocked) {
        return {
          allowed: false,
          reason: 'Destination in blacklist',
          action: 'block'
        };
      }
    }

    if (rule.allowedDestinations && rule.allowedDestinations.length > 0) {
      const allowed = rule.allowedDestinations.some(ruleDest =>
        this.matchDestination(dest, ruleDest)
      );

      if (!allowed) {
        return {
          allowed: false,
          reason: 'Destination not in whitelist',
          action: 'block'
        };
      }
    }

    if (rule.action === 'prompt') {
      return {
        allowed: false,
        reason: 'Application rule requires user approval',
        action: 'prompt',
        promptRequired: true
      };
    }

    if (rule.action === 'block') {
      return {
        allowed: false,
        reason: 'Application rule blocked request',
        action: 'block'
      };
    }

    return {
      allowed: true,
      reason: 'Passed application rule checks',
      action: 'allow'
    };
  }
}

// ==================== EXPORT INSTANCES ====================

export const dpi = new DeepPacketInspector();
export const ips = new IntrusionPreventionSystem();
export const appFirewall = new ApplicationFirewall();
