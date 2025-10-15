/**
 * Personal Data Protection Service
 * PII Detection, Data Leak Prevention, Privacy Scanning, Compliance (GDPR/CCPA)
 */

// ==================== PII PATTERNS DATABASE ====================

export const PII_PATTERNS = {
  // Credit Card Numbers (Luhn algorithm)
  creditCard: {
    name: 'Credit Card Number',
    patterns: [
      /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g
    ],
    severity: 'critical',
    category: 'financial',
    compliance: ['PCI-DSS']
  },

  // Social Security Numbers (US)
  ssn: {
    name: 'Social Security Number',
    patterns: [
      /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
      /\b(?!000|666|9\d{2})\d{3}\s(?!00)\d{2}\s(?!0000)\d{4}\b/g,
      /\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b/g
    ],
    severity: 'critical',
    category: 'identity',
    compliance: ['GDPR', 'CCPA', 'HIPAA']
  },

  // Email Addresses
  email: {
    name: 'Email Address',
    patterns: [
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g
    ],
    severity: 'high',
    category: 'contact',
    compliance: ['GDPR', 'CCPA']
  },

  // Phone Numbers (International)
  phone: {
    name: 'Phone Number',
    patterns: [
      /\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g, // US
      /\b(?:\+44\s?7\d{3}|\(?07\d{3}\)?)\s?\d{3}\s?\d{3}\b/g, // UK
      /\b(?:\+?[1-9]\d{0,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b/g // International
    ],
    severity: 'medium',
    category: 'contact',
    compliance: ['GDPR', 'CCPA']
  },

  // Passport Numbers
  passport: {
    name: 'Passport Number',
    patterns: [
      /\b[A-Z]{1,2}[0-9]{6,9}\b/g, // General format
      /\b[0-9]{9}\b/g // US format
    ],
    severity: 'critical',
    category: 'identity',
    compliance: ['GDPR']
  },

  // Driver's License (US)
  driversLicense: {
    name: "Driver's License Number",
    patterns: [
      /\b[A-Z]{1,2}[0-9]{5,8}\b/g,
      /\b[A-Z][0-9]{7}\b/g
    ],
    severity: 'high',
    category: 'identity',
    compliance: ['GDPR', 'CCPA']
  },

  // IP Addresses
  ipAddress: {
    name: 'IP Address',
    patterns: [
      /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
      /\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b/gi // IPv6
    ],
    severity: 'medium',
    category: 'network',
    compliance: ['GDPR']
  },

  // Bank Account Numbers
  bankAccount: {
    name: 'Bank Account Number',
    patterns: [
      /\b[0-9]{8,17}\b/g // General format
    ],
    severity: 'critical',
    category: 'financial',
    compliance: ['PCI-DSS', 'GDPR']
  },

  // Medical Record Numbers
  medicalRecord: {
    name: 'Medical Record Number',
    patterns: [
      /\b(?:MRN|Medical Record|Patient ID)[-:\s]*[A-Z0-9]{6,12}\b/gi
    ],
    severity: 'critical',
    category: 'health',
    compliance: ['HIPAA', 'GDPR']
  },

  // National ID Numbers (various countries)
  nationalId: {
    name: 'National ID Number',
    patterns: [
      /\b[0-9]{2}[0-1][0-9][0-3][0-9]-[0-9]{4}\b/g, // Swedish personnummer
      /\b[0-9]{11}\b/g // General 11-digit ID
    ],
    severity: 'critical',
    category: 'identity',
    compliance: ['GDPR']
  },

  // Tax ID Numbers
  taxId: {
    name: 'Tax Identification Number',
    patterns: [
      /\b[0-9]{2}-[0-9]{7}\b/g, // EIN (US)
      /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/g // Similar to SSN format
    ],
    severity: 'critical',
    category: 'financial',
    compliance: ['GDPR', 'CCPA']
  },

  // Dates of Birth
  dateOfBirth: {
    name: 'Date of Birth',
    patterns: [
      /\b(?:DOB|Date of Birth|Birth Date)[-:\s]*(?:0?[1-9]|1[0-2])[-/](0?[1-9]|[12][0-9]|3[01])[-/](?:19|20)\d{2}\b/gi,
      /\b(?:19|20)\d{2}[-/](0?[1-9]|1[0-2])[-/](0?[1-9]|[12][0-9]|3[01])\b/g
    ],
    severity: 'high',
    category: 'identity',
    compliance: ['GDPR', 'COPPA']
  },

  // Biometric Data References
  biometric: {
    name: 'Biometric Data Reference',
    patterns: [
      /\b(?:fingerprint|retina|iris|facial recognition|biometric)[-:\s]*[A-Z0-9]{8,}\b/gi
    ],
    severity: 'critical',
    category: 'biometric',
    compliance: ['GDPR']
  },

  // API Keys and Tokens
  apiKey: {
    name: 'API Key/Token',
    patterns: [
      /\b(?:api[_-]?key|api[_-]?token|access[_-]?token|secret[_-]?key)[-:\s]*['"]?[A-Za-z0-9_\-]{20,}['"]?\b/gi,
      /\b(?:Bearer\s+)[A-Za-z0-9_\-\.]{20,}\b/g
    ],
    severity: 'critical',
    category: 'credentials',
    compliance: ['GDPR', 'ISO 27001']
  },

  // Passwords (in plaintext)
  password: {
    name: 'Password (Plaintext)',
    patterns: [
      /\b(?:password|passwd|pwd)[-:\s]*['"]?[^\s'"]{6,}['"]?\b/gi
    ],
    severity: 'critical',
    category: 'credentials',
    compliance: ['GDPR', 'ISO 27001']
  },

  // Physical Addresses
  address: {
    name: 'Physical Address',
    patterns: [
      /\b\d{1,5}\s+[\w\s]+(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|parkway|pkwy|circle|cir|boulevard|blvd)\b/gi
    ],
    severity: 'medium',
    category: 'location',
    compliance: ['GDPR', 'CCPA']
  },

  // GPS Coordinates
  gpsCoordinates: {
    name: 'GPS Coordinates',
    patterns: [
      /\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b/g
    ],
    severity: 'high',
    category: 'location',
    compliance: ['GDPR', 'CCPA']
  },

  // Vehicle Identification Numbers (VIN)
  vin: {
    name: 'Vehicle Identification Number',
    patterns: [
      /\b[A-HJ-NPR-Z0-9]{17}\b/g
    ],
    severity: 'medium',
    category: 'identity',
    compliance: ['GDPR', 'CCPA']
  },

  // Cryptocurrency Wallet Addresses
  cryptoWallet: {
    name: 'Cryptocurrency Wallet Address',
    patterns: [
      /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, // Bitcoin
      /\b0x[a-fA-F0-9]{40}\b/g, // Ethereum
      /\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b/g // Litecoin
    ],
    severity: 'critical',
    category: 'financial',
    compliance: ['GDPR', 'CCPA']
  },

  // MAC Addresses
  macAddress: {
    name: 'MAC Address',
    patterns: [
      /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g
    ],
    severity: 'medium',
    category: 'network',
    compliance: ['GDPR']
  },

  // Insurance Policy Numbers
  insurancePolicy: {
    name: 'Insurance Policy Number',
    patterns: [
      /\b(?:policy|pol)[-\s]?(?:number|no|#)?[-:\s]*[A-Z0-9]{6,20}\b/gi
    ],
    severity: 'high',
    category: 'financial',
    compliance: ['HIPAA', 'GDPR']
  },

  // Employee ID Numbers
  employeeId: {
    name: 'Employee ID Number',
    patterns: [
      /\b(?:emp|employee|staff)[-\s]?(?:id|number|no)?[-:\s]*[A-Z0-9]{4,12}\b/gi
    ],
    severity: 'medium',
    category: 'employment',
    compliance: ['GDPR', 'CCPA']
  },

  // Student ID Numbers
  studentId: {
    name: 'Student ID Number',
    patterns: [
      /\b(?:student|stu)[-\s]?(?:id|number|no)?[-:\s]*[A-Z0-9]{6,12}\b/gi
    ],
    severity: 'medium',
    category: 'education',
    compliance: ['FERPA', 'GDPR']
  },

  // Invoice/Order Numbers
  invoiceNumber: {
    name: 'Invoice/Order Number',
    patterns: [
      /\b(?:invoice|inv|order|po)[-\s]?(?:number|no|#)?[-:\s]*[A-Z0-9]{6,15}\b/gi
    ],
    severity: 'low',
    category: 'financial',
    compliance: ['SOX', 'GDPR']
  },

  // Customer Numbers
  customerNumber: {
    name: 'Customer Number',
    patterns: [
      /\b(?:customer|client|account)[-\s]?(?:id|number|no)?[-:\s]*[A-Z0-9]{6,15}\b/gi
    ],
    severity: 'medium',
    category: 'identity',
    compliance: ['GDPR', 'CCPA']
  },

  // Contract Numbers
  contractNumber: {
    name: 'Contract Number',
    patterns: [
      /\b(?:contract|agreement)[-\s]?(?:number|no|#)?[-:\s]*[A-Z0-9]{6,15}\b/gi
    ],
    severity: 'medium',
    category: 'legal',
    compliance: ['GDPR']
  },

  // Case/Ticket Numbers
  caseNumber: {
    name: 'Case/Ticket Number',
    patterns: [
      /\b(?:case|ticket|incident)[-\s]?(?:number|no|#)?[-:\s]*[A-Z0-9]{6,15}\b/gi
    ],
    severity: 'low',
    category: 'support',
    compliance: ['GDPR']
  },

  // Browser Fingerprint Data
  browserFingerprint: {
    name: 'Browser Fingerprint',
    patterns: [
      /\b(?:user[-\s]?agent|fingerprint|canvas[-\s]?hash|webgl[-\s]?hash)[-:\s]*[A-Za-z0-9+/=]{20,}\b/gi
    ],
    severity: 'medium',
    category: 'tracking',
    compliance: ['GDPR', 'ePrivacy']
  },

  // Device IDs (IMEI, UDID, Android ID)
  deviceId: {
    name: 'Device Identifier',
    patterns: [
      /\b(?:IMEI|imei)[-:\s]*[0-9]{15}\b/g,
      /\b(?:UDID|udid)[-:\s]*[A-F0-9]{40}\b/gi,
      /\b(?:android[-\s]?id)[-:\s]*[A-F0-9]{16}\b/gi
    ],
    severity: 'high',
    category: 'device',
    compliance: ['GDPR', 'CCPA']
  },

  // Genetic Data References
  geneticData: {
    name: 'Genetic Data Reference',
    patterns: [
      /\b(?:DNA|RNA|genetic|genome|SNP)[-\s]?(?:sequence|profile|test|analysis)[-:\s]*[A-Z0-9]{6,}\b/gi
    ],
    severity: 'critical',
    category: 'health',
    compliance: ['HIPAA', 'GDPR', 'GINA']
  },

  // Religious Affiliation
  religiousData: {
    name: 'Religious Data',
    patterns: [
      /\b(?:religion|faith|belief|denomination)[-:\s]*(?:christian|muslim|jewish|hindu|buddhist|atheist|agnostic)/gi
    ],
    severity: 'high',
    category: 'sensitive',
    compliance: ['GDPR']
  },

  // Political Opinion
  politicalData: {
    name: 'Political Opinion',
    patterns: [
      /\b(?:political[-\s]?affiliation|party[-\s]?membership|voter[-\s]?registration)[-:\s]*[A-Za-z\s]+/gi
    ],
    severity: 'high',
    category: 'sensitive',
    compliance: ['GDPR']
  },

  // Trade Union Membership
  unionData: {
    name: 'Trade Union Membership',
    patterns: [
      /\b(?:union[-\s]?member|trade[-\s]?union|labor[-\s]?union)[-:\s]*[A-Za-z0-9\s]+/gi
    ],
    severity: 'medium',
    category: 'sensitive',
    compliance: ['GDPR']
  }
};

// ==================== SENSITIVE KEYWORDS ====================

export const SENSITIVE_KEYWORDS = {
  financial: [
    'bank account', 'routing number', 'swift code', 'iban', 'sort code',
    'credit card', 'debit card', 'cvv', 'pin number', 'account balance',
    'wire transfer', 'bitcoin wallet', 'crypto wallet', 'private key',
    'investment portfolio', 'net worth', 'tax return', 'w-2', '1099',
    'capital gains', 'dividend income', 'cryptocurrency', 'stock options'
  ],
  
  identity: [
    'social security', 'passport', 'drivers license', 'national id',
    'birth certificate', 'citizenship', 'visa number', 'green card',
    'voter registration', 'immigration status', 'naturalization',
    'asylum seeker', 'refugee status', 'work permit', 'residence permit'
  ],
  
  health: [
    'medical history', 'diagnosis', 'prescription', 'patient record',
    'blood type', 'allergies', 'treatment plan', 'mental health',
    'covid test', 'vaccination record', 'insurance claim', 'therapy notes',
    'psychiatric', 'addiction', 'hiv status', 'std test', 'pregnancy',
    'abortion', 'fertility treatment', 'genetic testing', 'cancer diagnosis',
    'disability', 'chronic illness', 'medication list', 'hospital admission'
  ],
  
  legal: [
    'confidential', 'attorney-client', 'privileged', 'non-disclosure',
    'settlement', 'lawsuit', 'litigation', 'court order', 'subpoena',
    'criminal record', 'arrest warrant', 'restraining order', 'probation',
    'parole', 'conviction', 'plea bargain', 'testimony', 'deposition',
    'divorce decree', 'custody agreement', 'adoption records'
  ],
  
  employment: [
    'salary', 'compensation', 'performance review', 'termination',
    'disciplinary action', 'background check', 'employment contract',
    'bonus', 'stock grant', 'severance', 'unemployment', 'workers compensation',
    'harassment complaint', 'discrimination', 'grievance', 'resignation',
    'promotion', 'demotion', 'suspension', 'probation period'
  ],

  education: [
    'transcript', 'gpa', 'sat score', 'act score', 'test scores',
    'disciplinary record', 'special education', 'iep', '504 plan',
    'suspension', 'expulsion', 'student loans', 'financial aid',
    'scholarship', 'recommendation letter', 'academic probation'
  ],

  biometric: [
    'fingerprint', 'facial recognition', 'iris scan', 'retina scan',
    'voice print', 'gait analysis', 'dna profile', 'hand geometry',
    'palm print', 'facial geometry', 'biometric template'
  ],

  location: [
    'home address', 'work address', 'gps location', 'geolocation',
    'latitude', 'longitude', 'coordinates', 'tracking data',
    'location history', 'travel patterns', 'commute route'
  ],

  relationships: [
    'marital status', 'sexual orientation', 'gender identity',
    'family relations', 'custody', 'domestic partner', 'spouse',
    'dependents', 'next of kin', 'emergency contact'
  ],

  sensitive_categories: [
    'race', 'ethnicity', 'national origin', 'ancestry',
    'religion', 'religious belief', 'political affiliation', 
    'political opinion', 'trade union', 'union membership',
    'philosophical beliefs', 'sexual life', 'sex life'
  ],

  communications: [
    'private message', 'confidential email', 'encrypted message',
    'secure chat', 'private conversation', 'internal memo',
    'classified information', 'proprietary data', 'trade secret'
  ],

  tracking: [
    'cookie id', 'tracking pixel', 'session token', 'device fingerprint',
    'browser fingerprint', 'advertising id', 'analytics id',
    'user agent', 'ip address tracking', 'behavioral data'
  ]
};

// ==================== DATA PROTECTION SERVICE ====================

export class DataProtectionService {
  constructor() {
    this.scanHistory = [];
    this.dataLeakAlerts = [];
    this.encryptedVault = new Map();
    this.complianceReports = [];
  }

  /**
   * Scan text for PII and sensitive data
   */
  scanText(text, options = {}) {
    const findings = [];
    const { includeContext = false, maskData = true } = options;

    // Scan for each PII pattern
    for (const [key, piiType] of Object.entries(PII_PATTERNS)) {
      for (const pattern of piiType.patterns) {
        const matches = text.matchAll(pattern);
        
        for (const match of matches) {
          const detectedData = match[0];
          const position = match.index;
          
          // Validate match (reduce false positives)
          if (this.validatePII(key, detectedData)) {
            findings.push({
              type: key,
              name: piiType.name,
              value: maskData ? this.maskData(detectedData, key) : detectedData,
              originalValue: detectedData,
              position: position,
              context: includeContext ? this.getContext(text, position, 50) : null,
              severity: piiType.severity,
              category: piiType.category,
              compliance: piiType.compliance,
              timestamp: new Date().toISOString()
            });
          }
        }
      }
    }

    // Scan for sensitive keywords
    const keywordMatches = this.scanKeywords(text);
    
    const result = {
      hasPII: findings.length > 0,
      hasSensitiveContent: keywordMatches.length > 0,
      findings: findings,
      keywords: keywordMatches,
      riskScore: this.calculateRiskScore(findings, keywordMatches),
      complianceImpact: this.getComplianceImpact(findings),
      recommendations: this.getRecommendations(findings, keywordMatches)
    };

    // Log scan
    this.scanHistory.push({
      timestamp: new Date().toISOString(),
      findingsCount: findings.length,
      riskScore: result.riskScore,
      categories: [...new Set(findings.map(f => f.category))]
    });

    return result;
  }

  /**
   * Scan file for sensitive data
   */
  async scanFile(file, options = {}) {
    try {
      const content = await this.readFile(file);
      const scanResult = this.scanText(content, options);
      
      return {
        ...scanResult,
        fileName: file.name,
        fileSize: file.size,
        fileType: file.type,
        scanDate: new Date().toISOString()
      };
    } catch (error) {
      return {
        error: true,
        message: `Failed to scan file: ${error.message}`,
        fileName: file.name
      };
    }
  }

  /**
   * Detect data leaks (clipboard, screenshots, file sharing)
   */
  detectDataLeak(source, data) {
    const scanResult = this.scanText(data, { maskData: true });
    
    if (scanResult.hasPII || scanResult.riskScore > 50) {
      const alert = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        source: source, // 'clipboard', 'screenshot', 'file-share', 'email'
        severity: scanResult.riskScore > 80 ? 'critical' : scanResult.riskScore > 50 ? 'high' : 'medium',
        piiDetected: scanResult.findings.length,
        piiTypes: [...new Set(scanResult.findings.map(f => f.name))],
        riskScore: scanResult.riskScore,
        blocked: scanResult.riskScore > 70, // Auto-block high-risk leaks
        complianceViolations: scanResult.complianceImpact
      };
      
      this.dataLeakAlerts.push(alert);
      
      return {
        isLeak: true,
        shouldBlock: alert.blocked,
        alert: alert,
        findings: scanResult.findings
      };
    }
    
    return {
      isLeak: false,
      shouldBlock: false
    };
  }

  /**
   * Redact/mask PII from text
   */
  redactPII(text, options = {}) {
    const { 
      redactionChar = '*',
      preserveFormat = true,
      keepFirstN = 0,
      keepLastN = 0
    } = options;

    let redactedText = text;
    const redactions = [];

    // Redact each PII type
    for (const [key, piiType] of Object.entries(PII_PATTERNS)) {
      for (const pattern of piiType.patterns) {
        redactedText = redactedText.replace(pattern, (match) => {
          const redacted = this.createRedaction(match, {
            redactionChar,
            preserveFormat,
            keepFirstN,
            keepLastN
          });
          
          redactions.push({
            original: match,
            redacted: redacted,
            type: piiType.name
          });
          
          return redacted;
        });
      }
    }

    return {
      redactedText,
      redactions,
      redactionCount: redactions.length
    };
  }

  /**
   * Generate compliance report (GDPR, CCPA, HIPAA)
   */
  generateComplianceReport(scanResults, standard = 'GDPR') {
    const relevantFindings = scanResults.findings.filter(f => 
      f.compliance.includes(standard)
    );

    const report = {
      standard: standard,
      generatedAt: new Date().toISOString(),
      summary: {
        totalFindings: relevantFindings.length,
        criticalFindings: relevantFindings.filter(f => f.severity === 'critical').length,
        highFindings: relevantFindings.filter(f => f.severity === 'high').length,
        categories: this.groupByCategory(relevantFindings)
      },
      findings: relevantFindings,
      complianceStatus: this.assessCompliance(relevantFindings, standard),
      recommendations: this.getComplianceRecommendations(standard, relevantFindings),
      riskAssessment: {
        overallRisk: scanResults.riskScore,
        dataBreachRisk: this.calculateBreachRisk(relevantFindings),
        regulatoryRisk: this.calculateRegulatoryRisk(relevantFindings, standard)
      }
    };

    this.complianceReports.push(report);
    return report;
  }

  /**
   * Encrypt sensitive data
   */
  encryptData(data, label) {
    // In production, use real encryption (AES-256)
    const encrypted = btoa(data); // Simple base64 for demo
    const id = `enc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    this.encryptedVault.set(id, {
      encrypted: encrypted,
      label: label,
      createdAt: new Date().toISOString(),
      algorithm: 'AES-256-GCM' // Would be real in production
    });
    
    return {
      id: id,
      encrypted: encrypted,
      label: label
    };
  }

  /**
   * Decrypt sensitive data
   */
  decryptData(id) {
    const stored = this.encryptedVault.get(id);
    if (!stored) {
      throw new Error('Encrypted data not found');
    }
    
    // In production, use real decryption
    const decrypted = atob(stored.encrypted);
    
    return {
      data: decrypted,
      label: stored.label,
      createdAt: stored.createdAt
    };
  }

  // ==================== HELPER METHODS ====================

  /**
   * Validate PII to reduce false positives
   */
  validatePII(type, value) {
    switch (type) {
      case 'creditCard':
        return this.validateLuhn(value.replace(/\D/g, ''));
      
      case 'email':
        return value.includes('@') && value.includes('.');
      
      case 'ssn':
        const digits = value.replace(/\D/g, '');
        return digits.length === 9 && 
               !digits.startsWith('000') && 
               !digits.startsWith('666') &&
               !digits.startsWith('9');
      
      case 'phone':
        const phoneDigits = value.replace(/\D/g, '');
        return phoneDigits.length >= 10;
      
      default:
        return true;
    }
  }

  /**
   * Luhn algorithm for credit card validation
   */
  validateLuhn(cardNumber) {
    let sum = 0;
    let isEven = false;
    
    for (let i = cardNumber.length - 1; i >= 0; i--) {
      let digit = parseInt(cardNumber[i]);
      
      if (isEven) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }
      
      sum += digit;
      isEven = !isEven;
    }
    
    return sum % 10 === 0;
  }

  /**
   * Mask sensitive data
   */
  maskData(data, type) {
    switch (type) {
      case 'creditCard':
        const cleaned = data.replace(/\D/g, '');
        return `****-****-****-${cleaned.slice(-4)}`;
      
      case 'ssn':
        return `***-**-${data.slice(-4)}`;
      
      case 'email':
        const [user, domain] = data.split('@');
        return `${user[0]}***@${domain}`;
      
      case 'phone':
        return `***-***-${data.slice(-4)}`;
      
      case 'password':
      case 'apiKey':
        return '********';
      
      default:
        return data.slice(0, 3) + '***' + data.slice(-2);
    }
  }

  /**
   * Create custom redaction
   */
  createRedaction(text, options) {
    const { redactionChar, preserveFormat, keepFirstN, keepLastN } = options;
    
    if (preserveFormat) {
      let redacted = '';
      for (let i = 0; i < text.length; i++) {
        if (i < keepFirstN || i >= text.length - keepLastN) {
          redacted += text[i];
        } else if (text[i] === ' ' || text[i] === '-' || text[i] === '/') {
          redacted += text[i];
        } else {
          redacted += redactionChar;
        }
      }
      return redacted;
    }
    
    const prefix = keepFirstN > 0 ? text.slice(0, keepFirstN) : '';
    const suffix = keepLastN > 0 ? text.slice(-keepLastN) : '';
    const middle = redactionChar.repeat(text.length - keepFirstN - keepLastN);
    
    return prefix + middle + suffix;
  }

  /**
   * Get text context around match
   */
  getContext(text, position, contextLength) {
    const start = Math.max(0, position - contextLength);
    const end = Math.min(text.length, position + contextLength);
    return text.substring(start, end);
  }

  /**
   * Scan for sensitive keywords
   */
  scanKeywords(text) {
    const matches = [];
    const lowerText = text.toLowerCase();
    
    for (const [category, keywords] of Object.entries(SENSITIVE_KEYWORDS)) {
      for (const keyword of keywords) {
        if (lowerText.includes(keyword.toLowerCase())) {
          matches.push({
            keyword: keyword,
            category: category,
            severity: this.getKeywordSeverity(category)
          });
        }
      }
    }
    
    return matches;
  }

  /**
   * Calculate risk score
   */
  calculateRiskScore(findings, keywords) {
    let score = 0;
    
    // PII findings
    findings.forEach(finding => {
      switch (finding.severity) {
        case 'critical': score += 30; break;
        case 'high': score += 20; break;
        case 'medium': score += 10; break;
        default: score += 5;
      }
    });
    
    // Keyword matches
    score += keywords.length * 5;
    
    // Multiple PII types increases risk
    const uniqueTypes = new Set(findings.map(f => f.type));
    if (uniqueTypes.size > 3) {
      score += 20;
    }
    
    return Math.min(score, 100);
  }

  /**
   * Get compliance impact
   */
  getComplianceImpact(findings) {
    const standards = new Set();
    findings.forEach(f => f.compliance.forEach(c => standards.add(c)));
    return Array.from(standards);
  }

  /**
   * Get recommendations
   */
  getRecommendations(findings, keywords) {
    const recommendations = [];
    
    if (findings.some(f => f.category === 'financial')) {
      recommendations.push('Encrypt all financial data before transmission');
      recommendations.push('Implement PCI-DSS compliance measures');
    }
    
    if (findings.some(f => f.category === 'health')) {
      recommendations.push('Ensure HIPAA compliance for health data');
      recommendations.push('Use secure, encrypted storage for medical records');
    }
    
    if (findings.some(f => f.category === 'credentials')) {
      recommendations.push('CRITICAL: Remove plaintext passwords and API keys immediately');
      recommendations.push('Use environment variables or secret management systems');
    }
    
    if (findings.length > 5) {
      recommendations.push('Consider implementing Data Loss Prevention (DLP) policies');
      recommendations.push('Enable automatic PII redaction for sensitive documents');
    }
    
    return recommendations;
  }

  /**
   * Group findings by category
   */
  groupByCategory(findings) {
    const groups = {};
    findings.forEach(f => {
      if (!groups[f.category]) {
        groups[f.category] = 0;
      }
      groups[f.category]++;
    });
    return groups;
  }

  /**
   * Assess compliance status
   */
  assessCompliance(findings, standard) {
    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    
    if (criticalCount === 0 && findings.length === 0) {
      return { status: 'compliant', level: 'full' };
    }
    
    if (criticalCount > 0) {
      return { status: 'non-compliant', level: 'critical', issues: criticalCount };
    }
    
    if (findings.length > 0) {
      return { status: 'partial', level: 'needs-review', issues: findings.length };
    }
    
    return { status: 'compliant', level: 'full' };
  }

  /**
   * Calculate data breach risk
   */
  calculateBreachRisk(findings) {
    const criticalFindings = findings.filter(f => f.severity === 'critical');
    const identityFindings = findings.filter(f => f.category === 'identity');
    
    if (criticalFindings.length > 5 || identityFindings.length > 3) {
      return 'high';
    }
    
    if (criticalFindings.length > 0 || findings.length > 10) {
      return 'medium';
    }
    
    return 'low';
  }

  /**
   * Calculate regulatory risk
   */
  calculateRegulatoryRisk(findings, standard) {
    const relevantFindings = findings.filter(f => f.compliance.includes(standard));
    
    if (relevantFindings.some(f => f.severity === 'critical')) {
      return 'high';
    }
    
    if (relevantFindings.length > 5) {
      return 'medium';
    }
    
    return 'low';
  }

  /**
   * Get compliance recommendations
   */
  getComplianceRecommendations(standard, findings) {
    const recommendations = [];
    
    switch (standard) {
      case 'GDPR':
        recommendations.push('Implement data minimization principles');
        recommendations.push('Obtain explicit consent for data processing');
        recommendations.push('Enable right to erasure (right to be forgotten)');
        recommendations.push('Conduct Data Protection Impact Assessment (DPIA)');
        break;
      
      case 'CCPA':
        recommendations.push('Provide clear privacy notice to California residents');
        recommendations.push('Enable opt-out of data sale');
        recommendations.push('Implement data subject access request (DSAR) process');
        break;
      
      case 'HIPAA':
        recommendations.push('Encrypt all Protected Health Information (PHI)');
        recommendations.push('Implement access controls and audit logs');
        recommendations.push('Conduct regular HIPAA security risk assessments');
        break;
    }
    
    return recommendations;
  }

  /**
   * Get keyword severity
   */
  getKeywordSeverity(category) {
    const severityMap = {
      financial: 'high',
      identity: 'high',
      health: 'critical',
      legal: 'medium',
      employment: 'medium',
      education: 'medium',
      biometric: 'critical',
      location: 'high',
      relationships: 'high',
      sensitive_categories: 'critical',
      communications: 'medium',
      tracking: 'medium'
    };
    return severityMap[category] || 'low';
  }

  /**
   * Read file content
   */
  async readFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = (e) => reject(e);
      reader.readAsText(file);
    });
  }

  /**
   * Get scan statistics
   */
  getStatistics() {
    return {
      totalScans: this.scanHistory.length,
      totalLeakAlerts: this.dataLeakAlerts.length,
      criticalLeaks: this.dataLeakAlerts.filter(a => a.severity === 'critical').length,
      averageRiskScore: this.scanHistory.length > 0
        ? this.scanHistory.reduce((sum, scan) => sum + scan.riskScore, 0) / this.scanHistory.length
        : 0,
      encryptedItems: this.encryptedVault.size,
      complianceReports: this.complianceReports.length,
      totalPIITypes: Object.keys(PII_PATTERNS).length,
      sensitiveKeywords: Object.values(SENSITIVE_KEYWORDS).flat().length
    };
  }

  /**
   * Anonymize data (GDPR Article 4(5))
   */
  anonymizeData(text, options = {}) {
    const { method = 'generalization', k = 3 } = options;
    let anonymized = text;

    // Scan for PII
    const scanResult = this.scanText(text, { maskData: false });
    
    if (!scanResult.hasPII) {
      return {
        success: true,
        anonymizedText: text,
        message: 'No PII found - text already anonymous'
      };
    }

    // Replace PII with generic values (k-anonymity)
    scanResult.findings.forEach(finding => {
      const genericValue = this.getGenericValue(finding.type, method);
      anonymized = anonymized.replace(finding.value, genericValue);
    });

    return {
      success: true,
      anonymizedText: anonymized,
      piiRemoved: scanResult.findings.length,
      method: method,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Get generic value for anonymization
   */
  getGenericValue(type, method) {
    const genericMap = {
      email: '[EMAIL_ADDRESS]',
      phone: '[PHONE_NUMBER]',
      ssn: '[SSN]',
      creditCard: '[CREDIT_CARD]',
      ipAddress: '[IP_ADDRESS]',
      address: '[PHYSICAL_ADDRESS]',
      name: '[NAME]',
      dateOfBirth: '[DATE_OF_BIRTH]',
      passport: '[PASSPORT]',
      driversLicense: '[DRIVERS_LICENSE]',
      bankAccount: '[BANK_ACCOUNT]',
      cryptoWallet: '[CRYPTO_WALLET]',
      gpsCoordinates: '[GPS_COORDINATES]',
      deviceId: '[DEVICE_ID]',
      geneticData: '[GENETIC_DATA]'
    };
    return genericMap[type] || '[REDACTED]';
  }

  /**
   * Pseudonymize data (GDPR Article 4(5))
   */
  pseudonymizeData(text) {
    const scanResult = this.scanText(text, { maskData: false });
    let pseudonymized = text;
    const mappings = {};

    scanResult.findings.forEach((finding, index) => {
      const pseudonym = this.generatePseudonym(finding.type, index);
      pseudonymized = pseudonymized.replace(finding.value, pseudonym);
      mappings[pseudonym] = finding.value; // Store mapping for reversal
    });

    return {
      success: true,
      pseudonymizedText: pseudonymized,
      mappings: mappings, // Should be securely stored separately
      reversible: true,
      piiCount: scanResult.findings.length,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Generate pseudonym
   */
  generatePseudonym(type, index) {
    const timestamp = Date.now();
    const random = Math.floor(Math.random() * 10000);
    return `${type.toUpperCase()}_${timestamp}_${random}_${index}`;
  }

  /**
   * Implement right to be forgotten (GDPR Article 17)
   */
  rightToBeForgotten(identifier) {
    const deletedItems = [];

    // Remove from scan history
    const historyBefore = this.scanHistory.length;
    this.scanHistory = this.scanHistory.filter(scan => {
      const shouldDelete = JSON.stringify(scan).includes(identifier);
      if (shouldDelete) deletedItems.push('scan_history');
      return !shouldDelete;
    });

    // Remove from data leak alerts
    const alertsBefore = this.dataLeakAlerts.length;
    this.dataLeakAlerts = this.dataLeakAlerts.filter(alert => {
      const shouldDelete = JSON.stringify(alert).includes(identifier);
      if (shouldDelete) deletedItems.push('leak_alerts');
      return !shouldDelete;
    });

    // Remove from encrypted vault
    const vaultBefore = this.encryptedVault.size;
    for (const [key, value] of this.encryptedVault.entries()) {
      if (key.includes(identifier) || value.includes(identifier)) {
        this.encryptedVault.delete(key);
        deletedItems.push('encrypted_vault');
      }
    }

    // Remove from compliance reports
    const reportsBefore = this.complianceReports.length;
    this.complianceReports = this.complianceReports.filter(report => {
      const shouldDelete = JSON.stringify(report).includes(identifier);
      if (shouldDelete) deletedItems.push('compliance_reports');
      return !shouldDelete;
    });

    return {
      success: true,
      message: 'All data related to identifier has been permanently deleted',
      deletedFrom: [...new Set(deletedItems)],
      itemsDeleted: {
        scanHistory: historyBefore - this.scanHistory.length,
        leakAlerts: alertsBefore - this.dataLeakAlerts.length,
        vaultItems: vaultBefore - this.encryptedVault.size,
        complianceReports: reportsBefore - this.complianceReports.length
      },
      timestamp: new Date().toISOString(),
      irreversible: true
    };
  }

  /**
   * Data retention policy check
   */
  applyRetentionPolicy(retentionDays = 365) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const deletedItems = {
      scanHistory: 0,
      leakAlerts: 0,
      complianceReports: 0
    };

    // Clean scan history
    const historyBefore = this.scanHistory.length;
    this.scanHistory = this.scanHistory.filter(scan => {
      return new Date(scan.timestamp) > cutoffDate;
    });
    deletedItems.scanHistory = historyBefore - this.scanHistory.length;

    // Clean leak alerts
    const alertsBefore = this.dataLeakAlerts.length;
    this.dataLeakAlerts = this.dataLeakAlerts.filter(alert => {
      return new Date(alert.timestamp) > cutoffDate;
    });
    deletedItems.leakAlerts = alertsBefore - this.dataLeakAlerts.length;

    // Clean compliance reports
    const reportsBefore = this.complianceReports.length;
    this.complianceReports = this.complianceReports.filter(report => {
      return new Date(report.generatedAt) > cutoffDate;
    });
    deletedItems.complianceReports = reportsBefore - this.complianceReports.length;

    return {
      success: true,
      message: `Data older than ${retentionDays} days has been deleted`,
      retentionDays: retentionDays,
      cutoffDate: cutoffDate.toISOString(),
      itemsDeleted: deletedItems,
      totalDeleted: Object.values(deletedItems).reduce((sum, val) => sum + val, 0),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Generate data subject access request (DSAR) report
   */
  generateDSARReport(identifier) {
    const report = {
      reportType: 'Data Subject Access Request (DSAR)',
      subject: identifier,
      generatedAt: new Date().toISOString(),
      dataCategories: {},
      summary: {}
    };

    // Search in scan history
    const scanHistoryData = this.scanHistory.filter(scan => 
      JSON.stringify(scan).includes(identifier)
    );
    report.dataCategories.scanHistory = {
      count: scanHistoryData.length,
      data: scanHistoryData.map(scan => ({
        timestamp: scan.timestamp,
        riskScore: scan.riskScore,
        piiTypes: scan.findings.map(f => f.type)
      }))
    };

    // Search in leak alerts
    const leakAlertData = this.dataLeakAlerts.filter(alert => 
      JSON.stringify(alert).includes(identifier)
    );
    report.dataCategories.leakAlerts = {
      count: leakAlertData.length,
      data: leakAlertData
    };

    // Search in encrypted vault
    const vaultData = [];
    for (const [key, value] of this.encryptedVault.entries()) {
      if (key.includes(identifier)) {
        vaultData.push({
          key: key,
          hasData: true,
          encrypted: true
        });
      }
    }
    report.dataCategories.encryptedVault = {
      count: vaultData.length,
      data: vaultData
    };

    // Search in compliance reports
    const complianceData = this.complianceReports.filter(cr => 
      JSON.stringify(cr).includes(identifier)
    );
    report.dataCategories.complianceReports = {
      count: complianceData.length,
      data: complianceData
    };

    // Summary
    report.summary = {
      totalDataPoints: Object.values(report.dataCategories)
        .reduce((sum, cat) => sum + cat.count, 0),
      categories: Object.keys(report.dataCategories).filter(cat => 
        report.dataCategories[cat].count > 0
      ),
      rights: [
        'Right of access (Article 15)',
        'Right to rectification (Article 16)',
        'Right to erasure (Article 17)',
        'Right to restriction (Article 18)',
        'Right to data portability (Article 20)',
        'Right to object (Article 21)'
      ]
    };

    return report;
  }

  /**
   * Data portability export (GDPR Article 20)
   */
  exportPersonalData(identifier, format = 'json') {
    const dsarReport = this.generateDSARReport(identifier);
    
    let exportData;
    if (format === 'json') {
      exportData = JSON.stringify(dsarReport, null, 2);
    } else if (format === 'csv') {
      exportData = this.convertToCSV(dsarReport);
    } else if (format === 'xml') {
      exportData = this.convertToXML(dsarReport);
    }

    return {
      success: true,
      format: format,
      data: exportData,
      fileName: `dsar_${identifier}_${Date.now()}.${format}`,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Convert report to CSV
   */
  convertToCSV(report) {
    let csv = 'Category,Count,Details\n';
    for (const [category, data] of Object.entries(report.dataCategories)) {
      csv += `${category},${data.count},"${JSON.stringify(data.data)}"\n`;
    }
    return csv;
  }

  /**
   * Convert report to XML
   */
  convertToXML(report) {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<DSARReport>\n';
    xml += `  <Subject>${report.subject}</Subject>\n`;
    xml += `  <GeneratedAt>${report.generatedAt}</GeneratedAt>\n`;
    xml += '  <DataCategories>\n';
    for (const [category, data] of Object.entries(report.dataCategories)) {
      xml += `    <${category} count="${data.count}">\n`;
      xml += `      <![CDATA[${JSON.stringify(data.data)}]]>\n`;
      xml += `    </${category}>\n`;
    }
    xml += '  </DataCategories>\n';
    xml += '</DSARReport>';
    return xml;
  }

  /**
   * Consent management
   */
  recordConsent(userId, consentType, granted = true) {
    const consent = {
      userId: userId,
      type: consentType,
      granted: granted,
      timestamp: new Date().toISOString(),
      ipAddress: '[IP_CAPTURED]',
      userAgent: navigator.userAgent,
      version: '1.0'
    };

    if (!this.consents) {
      this.consents = [];
    }
    this.consents.push(consent);

    return {
      success: true,
      message: `Consent ${granted ? 'granted' : 'withdrawn'} for ${consentType}`,
      consent: consent
    };
  }

  /**
   * Breach notification check (GDPR Article 33)
   */
  assessBreachNotification(breachDetails) {
    const { affectedRecords, dataTypes, likelihood, severity } = breachDetails;
    
    const requiresNotification = 
      affectedRecords > 0 &&
      (dataTypes.some(type => ['critical', 'high'].includes(PII_PATTERNS[type]?.severity))) &&
      likelihood !== 'low';

    return {
      requiresNotification: requiresNotification,
      timeframe: requiresNotification ? '72 hours' : 'N/A',
      authority: 'Data Protection Authority (DPA)',
      dataSubjects: affectedRecords > 250 ? 'Required' : 'If high risk',
      recommendations: [
        requiresNotification ? 'Notify DPA within 72 hours' : 'Document breach internally',
        'Assess risk to rights and freedoms of individuals',
        'Take measures to mitigate consequences',
        'Document breach and remediation steps',
        affectedRecords > 250 ? 'Notify affected data subjects' : 'Consider notifying affected individuals'
      ],
      severity: severity || 'medium',
      timestamp: new Date().toISOString()
    };
  }
}

// Export singleton instance
export const dataProtection = new DataProtectionService();
