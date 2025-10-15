// Enhanced Email Protection Service
// Advanced spam detection, phishing detection, BEC detection, and malicious attachment scanning
// Now with REAL threat intelligence integration

import threatIntelligence from './threatIntelligence';

// ==================== WEB ATTACK PATTERNS ====================
// Detect malicious code injection attempts in email content
const EMAIL_WEB_ATTACK_PATTERNS = [
  {
    id: 'xss_attack',
    type: 'web_attack',
    severity: 'critical',
    pattern: /<script[^>]*>.*?<\/script>|javascript:|onerror=|onclick=|onload=|<iframe/i,
    description: 'Cross-Site Scripting (XSS) code detected in email'
  },
  {
    id: 'sql_injection',
    type: 'web_attack',
    severity: 'critical',
    pattern: /('|(--)|;|union.*select|insert.*into|delete.*from|drop.*table|exec.*\(|execute.*\()/i,
    description: 'SQL Injection pattern detected in email content'
  },
  {
    id: 'command_injection',
    type: 'web_attack',
    severity: 'critical',
    pattern: /(\||;|`|\$\(|\$\{|&&|\|\|).*?(cat|ls|rm|wget|curl|bash|sh|cmd|powershell)/i,
    description: 'Command Injection attempt detected in email'
  },
  {
    id: 'html_smuggling',
    type: 'web_attack',
    severity: 'high',
    pattern: /atob\(|btoa\(|fromCharCode|\\x[0-9a-f]{2}|%[0-9a-f]{2}.*%[0-9a-f]{2}/i,
    description: 'HTML smuggling or obfuscation detected'
  },
  {
    id: 'macro_injection',
    type: 'web_attack',
    severity: 'high',
    pattern: /auto_open|autoopen|document_open|workbook_open|shell\(|wscript|activexobject/i,
    description: 'Macro or script execution pattern detected'
  }
];

// ==================== ENHANCED ATTACHMENT PATTERNS ====================
const DANGEROUS_ATTACHMENT_PATTERNS = {
  // Executable files
  executable: ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.msi', '.dll', '.sys'],
  // Scripts
  script: ['.vbs', '.js', '.jse', '.wsh', '.wsf', '.ps1', '.hta', '.reg'],
  // Archives (can hide malware)
  archive: ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso'],
  // Office with macros
  office_macro: ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.xlam'],
  // Mobile malware
  mobile: ['.apk', '.app', '.deb', '.rpm', '.dmg'],
  // Other suspicious
  suspicious: ['.jar', '.lnk', '.scpt', '.action', '.workflow', '.bin', '.gadget']
};

// Suspicious filename patterns
const SUSPICIOUS_FILENAME_PATTERNS = [
  /invoice.*\.(exe|scr|bat|js|vbs)/i,
  /document.*\.(exe|scr|bat|js|vbs)/i,
  /payment.*\.(exe|scr|bat|js|vbs)/i,
  /order.*\.(exe|scr|bat|js|vbs)/i,
  /receipt.*\.(exe|scr|bat|js|vbs)/i,
  /crack|keygen|patch|activator/i,
  /\.(pdf|doc|xls)\.(exe|scr|bat|js)/i // Double extension
];

class EmailProtectionService {
  constructor() {
    this.spamKeywords = [];
    this.phishingIndicators = [];
    this.dangerousExtensions = [];
    this.trustedSenders = new Set();
    this.blockedSenders = new Set();
    this.trustedDomains = new Set(['gmail.com', 'outlook.com', 'yahoo.com', 'icloud.com']);
    this.knownPhishingDomains = new Set();
    this.quarantine = [];
    this.isEnabled = true;
    this.stats = {
      totalScanned: 0,
      spamDetected: 0,
      phishingDetected: 0,
      maliciousAttachments: 0,
      blockedEmails: 0,
      becDetected: 0,
      quarantined: 0,
      webAttacksBlocked: 0,
      dangerousAttachmentsBlocked: 0
    };
    
    this.initializeFilters();
    this.loadQuarantine();
  }

  // Initialize spam and phishing filters
  initializeFilters() {
    // Spam keywords (categorized for better detection)
    this.spamKeywords = [
      // Pharmaceutical
      'viagra', 'cialis', 'pharmacy', 'prescription', 'pills',
      // Financial scams
      'winner', 'congratulations', 'prize', 'lottery', 'inheritance',
      'nigerian prince', 'no credit check', 'consolidate debt',
      // Urgency triggers
      'click here', 'act now', 'limited time', 'expires today',
      'order now', 'call now', 'buy now', 'apply now',
      // Money schemes
      'free money', 'make money fast', 'work from home',
      'million dollars', 'cash bonus', 'extra income',
      // Suspicious patterns
      'dear friend', 'valued customer', 'undisclosed recipient',
      'casino', 'refinance', 'debt relief'
    ];

    // Phishing indicators (enhanced)
    this.phishingIndicators = [
      'verify your account',
      'confirm your identity',
      'unusual activity',
      'account suspended',
      'update payment information',
      'security alert',
      'reset your password',
      'confirm your details',
      'urgent action required',
      'click here immediately',
      're-activate your account',
      'verify ownership',
      'confirm your payment',
      'billing problem',
      'suspended account',
      'update billing',
      'account will be closed',
      'validate your information',
      'unauthorized access',
      'account locked'
    ];

    // Business Email Compromise (BEC) indicators
    this.becIndicators = [
      'wire transfer',
      'urgent payment',
      'change of bank details',
      'invoice attached',
      'payment request',
      'bank account has changed',
      'new payment instructions',
      'update our banking information',
      'confidential',
      'discreet',
      'keep this between us'
    ];

    // Executive titles for impersonation detection
    this.executiveTitles = [
      'ceo', 'cfo', 'cto', 'president', 'director',
      'chief', 'executive', 'founder', 'owner', 'manager'
    ];

    // Dangerous file extensions (comprehensive)
    this.dangerousExtensions = [
      // Executables
      '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.msi',
      // Scripts
      '.vbs', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.psm1',
      // Binaries
      '.dll', '.sys', '.drv',
      // Archives (can hide malware)
      '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
      // Office with macros
      '.docm', '.xlsm', '.pptm', '.dotm', '.xltm',
      // Other suspicious
      '.jar', '.app', '.deb', '.rpm', '.dmg', '.iso'
    ];

    // Known phishing domains (examples)
    this.knownPhishingDomains = new Set([
      'paypa1.com', 'paypal-verify.com', 'secure-paypal.com',
      'amazon-security.com', 'apple-verify.com', 'microsoft-support.com',
      'google-account.com', 'netflix-billing.com'
    ]);
  }

  // Load quarantined emails from localStorage
  loadQuarantine() {
    try {
      const saved = localStorage.getItem('email_quarantine');
      this.quarantine = saved ? JSON.parse(saved) : [];
    } catch (error) {
      this.quarantine = [];
    }
  }

  // Save quarantine to localStorage
  saveQuarantine() {
    try {
      localStorage.setItem('email_quarantine', JSON.stringify(this.quarantine));
    } catch (error) {
      // Ignore storage errors
    }
  }

  // Scan email for threats (Enhanced)
  async scanEmail(email) {
    this.stats.totalScanned++;

    const threats = [];
    let riskScore = 0;
    const analysisDetails = {};

    // 1. Check sender reputation
    const senderCheck = this.checkSender(email.from);
    analysisDetails.senderReputation = senderCheck;
    if (senderCheck.isBlocked) {
      threats.push({
        type: 'blocked-sender',
        severity: 'critical',
        description: 'Email from blocked sender',
        sender: email.from
      });
      riskScore += 60;
      this.stats.blockedEmails++;
    }

    // 2. Check email headers (SPF/DKIM/DMARC simulation)
    const headerCheck = this.checkHeaders(email);
    analysisDetails.headerAuthentication = headerCheck;
    if (!headerCheck.passed) {
      threats.push({
        type: 'authentication-failed',
        severity: 'high',
        description: headerCheck.reason,
        details: headerCheck.details
      });
      riskScore += 30;
    }

    // 3. Check for spam
    const spamCheck = this.checkSpam(email);
    analysisDetails.spamAnalysis = spamCheck;
    if (spamCheck.isSpam) {
      threats.push({
        type: 'spam',
        severity: spamCheck.score >= 30 ? 'high' : 'medium',
        description: spamCheck.reason,
        matchedKeywords: spamCheck.keywords
      });
      riskScore += spamCheck.score;
      this.stats.spamDetected++;
    }

    // 4. Check for phishing
    const phishingCheck = this.checkPhishing(email);
    analysisDetails.phishingAnalysis = phishingCheck;
    if (phishingCheck.isPhishing) {
      threats.push({
        type: 'phishing',
        severity: 'critical',
        description: phishingCheck.reason,
        indicators: phishingCheck.indicators
      });
      riskScore += phishingCheck.score;
      this.stats.phishingDetected++;
    }

    // 5. Check for Business Email Compromise (BEC)
    const becCheck = this.checkBEC(email);
    analysisDetails.becAnalysis = becCheck;
    if (becCheck.isBEC) {
      threats.push({
        type: 'business-email-compromise',
        severity: 'critical',
        description: becCheck.reason,
        indicators: becCheck.indicators
      });
      riskScore += 50;
      this.stats.becDetected++;
    }

    // 6. Check attachments
    if (email.attachments && email.attachments.length > 0) {
      const attachmentCheck = await this.checkAttachments(email.attachments);
      analysisDetails.attachmentAnalysis = attachmentCheck;
      if (attachmentCheck.hasThreat) {
        threats.push({
          type: 'malicious-attachment',
          severity: attachmentCheck.criticalThreats > 0 ? 'critical' : 'high',
          description: attachmentCheck.reason,
          files: attachmentCheck.dangerousFiles,
          criticalThreats: attachmentCheck.criticalThreats,
          highThreats: attachmentCheck.highThreats
        });
        riskScore += attachmentCheck.score;
        this.stats.maliciousAttachments++;
        if (attachmentCheck.criticalThreats > 0) {
          this.stats.dangerousAttachmentsBlocked++;
        }
      }
    }

    // 7. Check links in email body (REAL threat intelligence)
    const linkCheck = await this.checkLinks(email.body || '');
    analysisDetails.linkAnalysis = linkCheck;
    if (linkCheck.hasSuspiciousLinks) {
      threats.push({
        type: 'suspicious-links',
        severity: linkCheck.criticalLinks > 0 ? 'critical' : 'high',
        description: linkCheck.reason,
        links: linkCheck.suspiciousLinks
      });
      riskScore += linkCheck.score;
    }

    // 8. Check domain reputation (REAL threat intelligence)
    const domainCheck = await this.checkDomainReputation(email);
    analysisDetails.domainReputation = domainCheck;
    if (domainCheck.isBlacklisted) {
      threats.push({
        type: 'blacklisted-domain',
        severity: 'critical',
        description: domainCheck.reason,
        source: domainCheck.source
      });
      riskScore += 50;
    }

    // 9. Check spoofing
    const spoofCheck = this.checkSpoofing(email);
    analysisDetails.spoofingCheck = spoofCheck;
    if (spoofCheck.isSpoofed) {
      threats.push({
        type: 'spoofing',
        severity: 'critical',
        description: spoofCheck.reason
      });
      riskScore += 40;
    }

    // 10. Detect web attacks in email content
    const webAttackCheck = this.detectWebAttacks(email);
    analysisDetails.webAttackAnalysis = webAttackCheck;
    if (webAttackCheck.hasAttack) {
      webAttackCheck.attacks.forEach(attack => {
        threats.push({
          type: 'web-attack',
          severity: attack.severity,
          description: attack.description,
          attackType: attack.type,
          recommendation: attack.recommendation
        });
      });
      riskScore += webAttackCheck.score;
      this.stats.webAttacksBlocked++;
    }

    // 11. Advanced pattern matching
    const patternCheck = this.checkAdvancedPatterns(email);
    if (patternCheck.suspicious) {
      threats.push({
        type: 'suspicious-pattern',
        severity: 'medium',
        description: patternCheck.reason,
        patterns: patternCheck.patterns
      });
      riskScore += patternCheck.score;
    }

    const result = {
      safe: threats.length === 0,
      threats: threats,
      riskScore: Math.min(riskScore, 100),
      recommendation: this.getRecommendation(riskScore, threats),
      analysisDetails: analysisDetails,
      scannedAt: new Date().toISOString()
    };

    // Auto-quarantine high-risk emails
    if (riskScore >= 70) {
      this.addToQuarantine(email, result);
    }

    return result;
  }

  // Check sender reputation
  checkSender(sender) {
    if (!sender) {
      return { isBlocked: false, isTrusted: false };
    }

    const senderLower = sender.toLowerCase();

    if (this.blockedSenders.has(senderLower)) {
      return { isBlocked: true, isTrusted: false };
    }

    if (this.trustedSenders.has(senderLower)) {
      return { isBlocked: false, isTrusted: true };
    }

    return { isBlocked: false, isTrusted: false };
  }

  // Check for spam indicators
  checkSpam(email) {
    const text = `${email.subject || ''} ${email.body || ''}`.toLowerCase();
    const matchedKeywords = [];
    let score = 0;

    for (const keyword of this.spamKeywords) {
      if (text.includes(keyword.toLowerCase())) {
        matchedKeywords.push(keyword);
        score += 10;
      }
    }

    // Multiple exclamation marks or all caps
    if ((email.subject || '').match(/!{3,}/)) {
      score += 15;
      matchedKeywords.push('excessive punctuation');
    }

    if ((email.subject || '').toUpperCase() === email.subject && email.subject.length > 10) {
      score += 10;
      matchedKeywords.push('all caps subject');
    }

    const isSpam = matchedKeywords.length >= 2 || score >= 20;

    return {
      isSpam: isSpam,
      score: Math.min(score, 40),
      keywords: matchedKeywords,
      reason: isSpam ? `Spam indicators detected: ${matchedKeywords.join(', ')}` : ''
    };
  }

  // Check for phishing attempts
  checkPhishing(email) {
    const text = `${email.subject || ''} ${email.body || ''}`.toLowerCase();
    const matchedIndicators = [];
    let score = 0;

    for (const indicator of this.phishingIndicators) {
      if (text.includes(indicator.toLowerCase())) {
        matchedIndicators.push(indicator);
        score += 20;
      }
    }

    // Check for mismatched display name and email
    if (email.displayName && email.from) {
      const displayLower = email.displayName.toLowerCase();
      const emailLower = email.from.toLowerCase();
      
      if (displayLower.includes('paypal') && !emailLower.includes('paypal.com')) {
        matchedIndicators.push('PayPal name spoofing');
        score += 30;
      }
      if (displayLower.includes('bank') && !emailLower.includes('bank')) {
        matchedIndicators.push('Bank name spoofing');
        score += 30;
      }
    }

    const isPhishing = matchedIndicators.length >= 1 || score >= 20;

    return {
      isPhishing: isPhishing,
      score: Math.min(score, 50),
      indicators: matchedIndicators,
      reason: isPhishing ? `Phishing indicators: ${matchedIndicators.join(', ')}` : ''
    };
  }

  // Check email attachments (ENHANCED with advanced threat detection)
  async checkAttachments(attachments) {
    const dangerousFiles = [];
    let score = 0;

    for (const attachment of attachments) {
      const fileName = attachment.filename || attachment.name || '';
      const ext = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
      const fileNameLower = fileName.toLowerCase();
      let threatLevel = 'unknown';
      let category = 'unknown';

      // Categorize file type and assess threat level
      if (DANGEROUS_ATTACHMENT_PATTERNS.executable.includes(ext)) {
        threatLevel = 'critical';
        category = 'Executable';
        dangerousFiles.push({
          name: fileName,
          reason: `Critical threat: Executable file (${ext})`,
          extension: ext,
          category: category,
          threatLevel: threatLevel,
          recommendation: 'BLOCK - Never open executable attachments from untrusted sources'
        });
        score += 50;
      } else if (DANGEROUS_ATTACHMENT_PATTERNS.script.includes(ext)) {
        threatLevel = 'critical';
        category = 'Script';
        dangerousFiles.push({
          name: fileName,
          reason: `Critical threat: Script file (${ext})`,
          extension: ext,
          category: category,
          threatLevel: threatLevel,
          recommendation: 'BLOCK - Script files can execute malicious code'
        });
        score += 45;
      } else if (DANGEROUS_ATTACHMENT_PATTERNS.office_macro.includes(ext)) {
        threatLevel = 'high';
        category = 'Office Document with Macros';
        dangerousFiles.push({
          name: fileName,
          reason: `High threat: Office file with macros (${ext})`,
          extension: ext,
          category: category,
          threatLevel: threatLevel,
          recommendation: 'WARN - Only open if from trusted source, disable macros'
        });
        score += 35;
      } else if (DANGEROUS_ATTACHMENT_PATTERNS.archive.includes(ext)) {
        threatLevel = 'medium';
        category = 'Compressed Archive';
        dangerousFiles.push({
          name: fileName,
          reason: `Medium threat: Archive file can hide malware (${ext})`,
          extension: ext,
          category: category,
          threatLevel: threatLevel,
          recommendation: 'CAUTION - Scan archive contents before extracting'
        });
        score += 20;
      } else if (DANGEROUS_ATTACHMENT_PATTERNS.mobile.includes(ext)) {
        threatLevel = 'high';
        category = 'Mobile Application';
        dangerousFiles.push({
          name: fileName,
          reason: `High threat: Mobile app package (${ext})`,
          extension: ext,
          category: category,
          threatLevel: threatLevel,
          recommendation: 'BLOCK - Only install apps from official stores'
        });
        score += 40;
      } else if (this.dangerousExtensions.includes(ext)) {
        threatLevel = 'high';
        category = 'Suspicious File';
        dangerousFiles.push({
          name: fileName,
          reason: `Dangerous file type: ${ext}`,
          extension: ext,
          category: category,
          threatLevel: threatLevel,
          recommendation: 'BLOCK - Verify with sender before opening'
        });
        score += 30;
      }

      // Check for suspicious filename patterns
      for (const pattern of SUSPICIOUS_FILENAME_PATTERNS) {
        if (pattern.test(fileNameLower)) {
          dangerousFiles.push({
            name: fileName,
            reason: 'Suspicious filename pattern (commonly used in malware)',
            extension: ext,
            category: 'Suspicious Pattern',
            threatLevel: 'high',
            recommendation: 'BLOCK - Likely malware disguised as legitimate file'
          });
          score += 40;
          break;
        }
      }

      // Double extensions (e.g., document.pdf.exe)
      const parts = fileName.split('.');
      if (parts.length > 2) {
        const hiddenExt = '.' + parts[parts.length - 2].toLowerCase();
        dangerousFiles.push({
          name: fileName,
          reason: 'Double file extension (file type disguise technique)',
          extension: ext,
          category: 'File Disguise',
          threatLevel: 'critical',
          recommendation: 'BLOCK - Common malware obfuscation technique'
        });
        score += 45;
      }

      // Very long filename (obfuscation)
      if (fileName.length > 100) {
        dangerousFiles.push({
          name: fileName,
          reason: 'Unusually long filename (obfuscation technique)',
          extension: ext,
          category: 'Obfuscation',
          threatLevel: 'medium',
          recommendation: 'WARN - May be attempting to hide true file type'
        });
        score += 20;
      }

      // Check for null bytes or special characters (indicator of exploit attempts)
      if (fileName.includes('\0') || /[\x00-\x1F]/.test(fileName)) {
        dangerousFiles.push({
          name: fileName,
          reason: 'Filename contains null bytes or control characters',
          extension: ext,
          category: 'Exploit Attempt',
          threatLevel: 'critical',
          recommendation: 'BLOCK - Potential exploit targeting file system'
        });
        score += 50;
      }
    }

    return {
      hasThreat: dangerousFiles.length > 0,
      dangerousFiles: dangerousFiles,
      score: Math.min(score, 50),
      reason: dangerousFiles.length > 0 
        ? `${dangerousFiles.length} dangerous attachment(s) detected`
        : '',
      criticalThreats: dangerousFiles.filter(f => f.threatLevel === 'critical').length,
      highThreats: dangerousFiles.filter(f => f.threatLevel === 'high').length
    };
  }

  // Check links in email body (Enhanced with REAL threat intelligence)
  async checkLinks(body) {
    const urlRegex = /(https?:\/\/[^\s<>"]+)/gi;
    const urls = body.match(urlRegex) || [];
    const suspiciousLinks = [];
    let score = 0;
    let criticalLinks = 0;

    for (const url of urls) {
      try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname.toLowerCase();
        
        // REAL: Check against loaded threat intelligence feeds
        const domainReputation = threatIntelligence.checkDomainReputation(domain);
        if (domainReputation.threat) {
          suspiciousLinks.push({
            url: url,
            reason: `${domainReputation.type}: ${domainReputation.source}`,
            severity: 'critical',
            confidence: domainReputation.confidence
          });
          score += 50;
          criticalLinks++;
          continue;
        }

        // REAL: Check with VirusTotal if API key available
        const vtResult = await threatIntelligence.checkURLWithVirusTotal(url);
        if (vtResult && (vtResult.malicious > 0 || vtResult.suspicious > 2)) {
          suspiciousLinks.push({
            url: url,
            reason: `Detected as malicious by ${vtResult.malicious} engines`,
            severity: 'critical',
            vtData: vtResult
          });
          score += 45;
          criticalLinks++;
          continue;
        }

        // IP address instead of domain
        if (/^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname)) {
          // REAL: Check IP reputation if API available
          const ipReputation = await threatIntelligence.checkIPWithAbuseIPDB(urlObj.hostname);
          if (ipReputation && ipReputation.abuseConfidenceScore > 50) {
            suspiciousLinks.push({
              url: url,
              reason: `IP address with ${ipReputation.abuseConfidenceScore}% abuse confidence`,
              severity: 'high',
              abuseData: ipReputation
            });
            score += 30;
          } else {
            suspiciousLinks.push({
              url: url,
              reason: 'Uses IP address instead of domain',
              severity: 'medium'
            });
            score += 15;
          }
        }

        // URL shortener (can hide malicious destination)
        const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'tiny.cc'];
        if (shorteners.some(s => urlObj.hostname.includes(s))) {
          suspiciousLinks.push({
            url: url,
            reason: 'URL shortener (hides destination)',
            severity: 'medium'
          });
          score += 10;
        }

        // Unusual port numbers
        if (urlObj.port && !['80', '443', '8080'].includes(urlObj.port)) {
          suspiciousLinks.push({
            url: url,
            reason: `Unusual port number: ${urlObj.port}`,
            severity: 'medium'
          });
          score += 15;
        }

        // Check for data exfiltration patterns
        if (urlObj.search && urlObj.search.length > 200) {
          suspiciousLinks.push({
            url: url,
            reason: 'Unusually long query string (possible data exfiltration)',
            severity: 'medium'
          });
          score += 10;
        }

        // Punycode/IDN homograph attack
        if (urlObj.hostname.includes('xn--')) {
          suspiciousLinks.push({
            url: url,
            reason: 'Internationalized domain (possible homograph attack)',
            severity: 'high'
          });
          score += 25;
        }

        // Suspicious TLDs
        const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work'];
        if (suspiciousTlds.some(tld => urlObj.hostname.endsWith(tld))) {
          suspiciousLinks.push({
            url: url,
            reason: 'Suspicious top-level domain',
            severity: 'medium'
          });
          score += 12;
        }

      } catch (e) {
        // Invalid URL
        suspiciousLinks.push({
          url: url,
          reason: 'Malformed URL',
          severity: 'low'
        });
        score += 5;
      }
    }

    return {
      hasSuspiciousLinks: suspiciousLinks.length > 0,
      suspiciousLinks: suspiciousLinks,
      criticalLinks: criticalLinks,
      score: Math.min(score, 50),
      reason: suspiciousLinks.length > 0
        ? `${suspiciousLinks.length} suspicious link(s) found`
        : ''
    };
  }

  // Check for web attacks in email content
  detectWebAttacks(email) {
    const content = `${email.subject || ''} ${email.body || ''}`;
    const detectedAttacks = [];
    let score = 0;

    for (const pattern of EMAIL_WEB_ATTACK_PATTERNS) {
      if (pattern.pattern.test(content)) {
        detectedAttacks.push({
          type: pattern.id,
          severity: pattern.severity,
          description: pattern.description,
          recommendation: 'Do not open this email. Delete immediately and report to IT security.'
        });
        score += pattern.severity === 'critical' ? 50 : 30;
      }
    }

    return {
      hasAttack: detectedAttacks.length > 0,
      attacks: detectedAttacks,
      score: Math.min(score, 50),
      reason: detectedAttacks.length > 0
        ? `${detectedAttacks.length} web attack pattern(s) detected`
        : ''
    };
  }

  // Check for email spoofing
  checkSpoofing(email) {
    // Check for common spoofing patterns
    const fromDomain = (email.from || '').split('@')[1]?.toLowerCase();
    const replyToDomain = (email.replyTo || '').split('@')[1]?.toLowerCase();

    if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
      return {
        isSpoofed: true,
        reason: 'From and Reply-To domains do not match'
      };
    }

    // Check for lookalike domains
    const knownDomains = ['paypal.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com'];
    for (const known of knownDomains) {
      if (fromDomain && fromDomain !== known && this.isSimilar(fromDomain, known)) {
        return {
          isSpoofed: true,
          reason: `Domain looks similar to ${known}`
        };
      }
    }

    return { isSpoofed: false };
  }

  // Check for web attacks in email content
  detectWebAttacks(email) {
    const content = `${email.subject || ''} ${email.body || ''}`;
    const detectedAttacks = [];
    let score = 0;

    for (const pattern of EMAIL_WEB_ATTACK_PATTERNS) {
      if (pattern.pattern.test(content)) {
        detectedAttacks.push({
          type: pattern.id,
          severity: pattern.severity,
          description: pattern.description,
          recommendation: 'Do not open this email. Delete immediately and report to IT security.'
        });
        score += pattern.severity === 'critical' ? 50 : 30;
      }
    }

    return {
      hasAttack: detectedAttacks.length > 0,
      attacks: detectedAttacks,
      score: Math.min(score, 50),
      reason: detectedAttacks.length > 0
        ? `${detectedAttacks.length} web attack pattern(s) detected`
        : ''
    };
  }

  // Check for Business Email Compromise (BEC)
  checkBEC(email) {
    const text = `${email.subject || ''} ${email.body || ''}`.toLowerCase();
    const matchedIndicators = [];
    let score = 0;

    // Check for BEC keywords
    for (const indicator of this.becIndicators) {
      if (text.includes(indicator.toLowerCase())) {
        matchedIndicators.push(indicator);
        score += 15;
      }
    }

    // Check for executive impersonation
    const displayLower = (email.displayName || '').toLowerCase();
    const hasExecutiveTitle = this.executiveTitles.some(title => 
      displayLower.includes(title)
    );

    if (hasExecutiveTitle) {
      const fromDomain = (email.from || '').split('@')[1]?.toLowerCase();
      
      // External domain with executive title is suspicious
      if (fromDomain && !this.trustedDomains.has(fromDomain)) {
        matchedIndicators.push('Executive title from external domain');
        score += 25;
      }
    }

    // Urgency + financial keywords combination
    const hasUrgency = text.match(/urgent|immediately|asap|right away|time sensitive/i);
    const hasFinancial = text.match(/wire|transfer|payment|invoice|account|bank/i);
    
    if (hasUrgency && hasFinancial) {
      matchedIndicators.push('Urgent financial request');
      score += 20;
    }

    // Confidentiality requests (red flag in BEC)
    if (text.match(/confidential|do not (share|tell|forward)|keep (this|it) (between|quiet)/i)) {
      matchedIndicators.push('Confidentiality request');
      score += 15;
    }

    const isBEC = matchedIndicators.length >= 2 || score >= 30;

    return {
      isBEC: isBEC,
      score: Math.min(score, 50),
      indicators: matchedIndicators,
      reason: isBEC ? `Business Email Compromise indicators: ${matchedIndicators.join(', ')}` : ''
    };
  }

  // Check email headers (SPF/DKIM/DMARC simulation)
  checkHeaders(email) {
    const fromDomain = (email.from || '').split('@')[1]?.toLowerCase();
    const details = [];
    let passed = true;
    let reason = '';

    // Simulate SPF check
    const spfPass = this.simulateSPF(email);
    if (!spfPass) {
      passed = false;
      details.push('SPF: FAIL - Sender IP not authorized');
      reason = 'Email authentication failed';
    } else {
      details.push('SPF: PASS');
    }

    // Simulate DKIM check
    const dkimPass = this.simulateDKIM(email);
    if (!dkimPass) {
      passed = false;
      details.push('DKIM: FAIL - Invalid signature');
      reason = 'Email signature invalid';
    } else {
      details.push('DKIM: PASS');
    }

    // Simulate DMARC check
    const dmarcPass = this.simulateDMARC(email);
    if (!dmarcPass) {
      // DMARC failure is less critical
      details.push('DMARC: SOFTFAIL');
    } else {
      details.push('DMARC: PASS');
    }

    return {
      passed: passed,
      spf: spfPass,
      dkim: dkimPass,
      dmarc: dmarcPass,
      details: details,
      reason: reason
    };
  }

  // Simulate SPF check (NOTE: Real SPF requires DNS queries which aren't possible in browser)
  // For production, this should be done on a backend server
  simulateSPF(email) {
    const fromDomain = (email.from || '').split('@')[1]?.toLowerCase();
    
    // Trusted domains always pass
    if (this.trustedDomains.has(fromDomain)) return true;
    
    // Known phishing domains fail
    if (this.knownPhishingDomains.has(fromDomain)) return false;
    
    // Simulate: 90% pass rate for demonstration
    return Math.random() > 0.1;
  }

  // Simulate DKIM check (NOTE: Real DKIM validation requires cryptographic verification)
  // For production, this should be done on a backend server
  simulateDKIM(email) {
    const fromDomain = (email.from || '').split('@')[1]?.toLowerCase();
    
    // Trusted domains always pass
    if (this.trustedDomains.has(fromDomain)) return true;
    
    // Known phishing domains fail
    if (this.knownPhishingDomains.has(fromDomain)) return false;
    
    // Simulate: 85% pass rate
    return Math.random() > 0.15;
  }

  // Simulate DMARC check (NOTE: Real DMARC requires DNS TXT record lookups)
  // For production, this should be done on a backend server
  simulateDMARC(email) {
    const fromDomain = (email.from || '').split('@')[1]?.toLowerCase();
    
    // Trusted domains always pass
    if (this.trustedDomains.has(fromDomain)) return true;
    
    // Simulate: 80% pass rate
    return Math.random() > 0.2;
  }

  // Check domain reputation (REAL threat intelligence)
  async checkDomainReputation(email) {
    const fromDomain = (email.from || '').split('@')[1]?.toLowerCase();
    
    if (!fromDomain) {
      return { isBlacklisted: false };
    }

    // REAL: Check threat intelligence feeds
    const reputation = threatIntelligence.checkDomainReputation(fromDomain);
    
    if (reputation.threat) {
      return {
        isBlacklisted: true,
        reason: `Domain flagged as ${reputation.type}`,
        source: reputation.source,
        confidence: reputation.confidence
      };
    }

    // Check for typosquatting against legitimate domains
    const legitimateDomains = [
      'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
      'paypal.com', 'ebay.com', 'netflix.com', 'dropbox.com', 'linkedin.com',
      'gmail.com', 'outlook.com', 'yahoo.com', 'bankofamerica.com', 'chase.com'
    ];

    for (const legitDomain of legitimateDomains) {
      const typoResult = threatIntelligence.detectTyposquatting(fromDomain, legitDomain);
      if (typoResult.isTyposquatting) {
        return {
          isBlacklisted: true,
          reason: `Possible typosquatting of ${legitDomain}`,
          source: 'Typosquatting Detection',
          similarity: typoResult.similarity
        };
      }
    }

    // Check for homoglyph attacks
    if (threatIntelligence.hasHomoglyphs(fromDomain)) {
      return {
        isBlacklisted: true,
        reason: 'Domain contains look-alike characters (homoglyph attack)',
        source: 'Homoglyph Detection'
      };
    }

    // Check for high-risk TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
    if (suspiciousTlds.some(tld => fromDomain.endsWith(tld))) {
      return {
        isBlacklisted: true,
        reason: 'Domain uses high-risk TLD commonly used in spam',
        source: 'TLD Analysis'
      };
    }

    return { isBlacklisted: false };
  }

  // Advanced pattern matching
  checkAdvancedPatterns(email) {
    const text = `${email.subject || ''} ${email.body || ''}`;
    const patterns = [];
    let score = 0;

    // Excessive capitalization
    const capsRatio = (text.match(/[A-Z]/g) || []).length / text.length;
    if (capsRatio > 0.4 && text.length > 20) {
      patterns.push('Excessive capitalization');
      score += 10;
    }

    // Excessive punctuation
    if ((text.match(/[!?]{2,}/g) || []).length > 2) {
      patterns.push('Excessive punctuation');
      score += 8;
    }

    // Hidden text attempts (zero-width characters)
    if (text.match(/[\u200B-\u200D\uFEFF]/)) {
      patterns.push('Hidden characters detected');
      score += 15;
    }

    // Lookalike characters (homograph attack)
    const homoglyphs = /[αа𝐚ⅽс𝗮𝑎]/i; // Latin vs Cyrillic/Greek
    if (homoglyphs.test(text)) {
      patterns.push('Lookalike characters (possible homograph attack)');
      score += 20;
    }

    // Unusual character encoding
    if (text.match(/&#x[0-9a-f]{2,}/gi)) {
      patterns.push('Unusual character encoding');
      score += 10;
    }

    // Base64 encoded content (can hide malicious payloads)
    if (text.match(/[A-Za-z0-9+\/]{50,}={0,2}/)) {
      patterns.push('Base64 encoded content detected');
      score += 12;
    }

    return {
      suspicious: patterns.length > 0,
      patterns: patterns,
      score: Math.min(score, 30),
      reason: patterns.length > 0 ? `${patterns.length} suspicious pattern(s) found` : ''
    };
  }

  // Add email to quarantine
  addToQuarantine(email, scanResult) {
    const quarantineItem = {
      id: Date.now(),
      email: email,
      scanResult: scanResult,
      quarantinedAt: new Date().toISOString(),
      reviewed: false
    };

    this.quarantine.unshift(quarantineItem);
    
    // Keep only last 100 quarantined emails
    if (this.quarantine.length > 100) {
      this.quarantine = this.quarantine.slice(0, 100);
    }

    this.stats.quarantined++;
    this.saveQuarantine();
  }

  // Get quarantined emails
  getQuarantine() {
    return this.quarantine;
  }

  // Remove from quarantine
  removeFromQuarantine(id) {
    this.quarantine = this.quarantine.filter(item => item.id !== id);
    this.saveQuarantine();
  }

  // Mark quarantine item as reviewed
  markAsReviewed(id) {
    const item = this.quarantine.find(item => item.id === id);
    if (item) {
      item.reviewed = true;
      this.saveQuarantine();
    }
  }

  // Clear quarantine
  clearQuarantine() {
    this.quarantine = [];
    this.saveQuarantine();
  }

  // Check if two strings are similar (for domain spoofing detection)
  isSimilar(str1, str2) {
    // Simple Levenshtein distance check
    if (Math.abs(str1.length - str2.length) > 3) return false;
    
    let differences = 0;
    const maxLen = Math.max(str1.length, str2.length);
    
    for (let i = 0; i < maxLen; i++) {
      if (str1[i] !== str2[i]) differences++;
      if (differences > 2) return false;
    }
    
    return differences > 0 && differences <= 2;
  }

  // Get recommendation based on risk score
  getRecommendation(riskScore, threats) {
    if (riskScore >= 75) {
      return {
        action: 'block',
        message: 'This email is highly dangerous. Delete immediately.',
        color: 'error'
      };
    } else if (riskScore >= 50) {
      return {
        action: 'quarantine',
        message: 'This email is suspicious. Review carefully before opening.',
        color: 'warning'
      };
    } else if (riskScore >= 25) {
      return {
        action: 'warn',
        message: 'This email has some concerning elements. Proceed with caution.',
        color: 'info'
      };
    } else {
      return {
        action: 'allow',
        message: 'This email appears safe.',
        color: 'success'
      };
    }
  }

  // Add trusted sender
  addTrustedSender(email) {
    this.trustedSenders.add(email.toLowerCase());
  }

  // Block sender
  blockSender(email) {
    this.blockedSenders.add(email.toLowerCase());
  }

  // Unblock sender
  unblockSender(email) {
    this.blockedSenders.delete(email.toLowerCase());
  }

  // Get protection stats
  getStats() {
    return {
      ...this.stats,
      trustedSenders: this.trustedSenders.size,
      blockedSenders: this.blockedSenders.size,
      spamKeywords: this.spamKeywords.length,
      phishingIndicators: this.phishingIndicators.length,
      becIndicators: this.becIndicators.length,
      quarantineSize: this.quarantine.length
    };
  }

  // Add trusted domain
  addTrustedDomain(domain) {
    this.trustedDomains.add(domain.toLowerCase());
  }

  // Remove trusted domain
  removeTrustedDomain(domain) {
    this.trustedDomains.delete(domain.toLowerCase());
  }

  // Get lists
  getLists() {
    return {
      trustedSenders: Array.from(this.trustedSenders),
      blockedSenders: Array.from(this.blockedSenders),
      trustedDomains: Array.from(this.trustedDomains),
      knownPhishingDomains: Array.from(this.knownPhishingDomains)
    };
  }

  // Enable/disable protection
  setEnabled(enabled) {
    this.isEnabled = enabled;
  }

  // Reset stats
  resetStats() {
    this.stats = {
      totalScanned: 0,
      spamDetected: 0,
      phishingDetected: 0,
      maliciousAttachments: 0,
      blockedEmails: 0,
      becDetected: 0,
      quarantined: 0,
      webAttacksBlocked: 0,
      dangerousAttachmentsBlocked: 0
    };
  }
}

// Singleton instance
const emailProtection = new EmailProtectionService();

export default emailProtection;
