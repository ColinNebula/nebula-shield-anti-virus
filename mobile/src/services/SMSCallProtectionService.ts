/**
 * SMS and Call Protection Service
 * Blocks spam calls/SMS and detects phishing attempts
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import { Platform } from 'react-native';
import ApiService from './ApiService';

export interface BlockedNumber {
  id: string;
  number: string;
  name?: string;
  type: 'spam' | 'scam' | 'telemarketer' | 'fraud' | 'robocall' | 'manual';
  blockedAt: string;
  blockCount: number;
  lastAttempt?: string;
  reportedBy: number; // Number of users who reported
}

export interface SMSMessage {
  id: string;
  from: string;
  senderName?: string;
  body: string;
  timestamp: string;
  isSpam: boolean;
  isPhishing: boolean;
  riskScore: number; // 0-100
  threatType?: 'phishing' | 'smishing' | 'spam' | 'scam';
  blockedReasons: string[];
}

export interface CallRecord {
  id: string;
  number: string;
  callerName?: string;
  timestamp: string;
  duration: number;
  type: 'incoming' | 'outgoing' | 'missed';
  isBlocked: boolean;
  isSpam: boolean;
  riskScore: number;
  country?: string;
  carrier?: string;
}

export interface ProtectionStats {
  totalBlocked: number;
  spamCallsBlocked: number;
  spamSMSBlocked: number;
  phishingAttempts: number;
  scamPrevented: number;
  todayBlocked: number;
  thisWeekBlocked: number;
  thisMonthBlocked: number;
  topSpamSources: Array<{
    number: string;
    count: number;
    type: string;
  }>;
}

export interface PhishingPattern {
  id: string;
  pattern: RegExp;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  examples: string[];
}

export interface SpamDatabase {
  version: string;
  lastUpdated: string;
  spamNumbers: number;
  scamPatterns: number;
  communityReports: number;
}

export interface ProtectionSettings {
  blockSpamCalls: boolean;
  blockSpamSMS: boolean;
  blockInternationalCalls: boolean;
  blockHiddenNumbers: boolean;
  detectPhishing: boolean;
  autoReportSpam: boolean;
  silenceUnknownCallers: boolean;
  allowContactsOnly: boolean;
  customBlockList: string[];
  customAllowList: string[];
}

export interface SpamReport {
  id: string;
  number: string;
  type: 'call' | 'sms';
  category: 'spam' | 'scam' | 'fraud' | 'phishing' | 'robocall';
  description?: string;
  reportedAt: string;
  status: 'pending' | 'verified' | 'rejected';
}

class SMSCallProtectionServiceClass {
  // Known spam number patterns
  private spamPatterns = [
    /^1?800\d{7}$/, // 800 numbers
    /^1?888\d{7}$/, // 888 numbers
    /^\+?1?900\d{7}$/, // Premium rate
    /^\d{5}$/, // Short codes (often spam)
  ];

  // Phishing SMS patterns
  private phishingPatterns: PhishingPattern[] = [
    {
      id: 'phish-1',
      pattern: /(verify|confirm|update).*account/i,
      description: 'Account verification scam',
      severity: 'high',
      examples: ['Verify your account', 'Confirm your payment method'],
    },
    {
      id: 'phish-2',
      pattern: /(click|tap).*link.*(urgent|expire|suspend|lock)/i,
      description: 'Urgent action scam',
      severity: 'critical',
      examples: ['Click this link urgently', 'Your account will be suspended'],
    },
    {
      id: 'phish-3',
      pattern: /(won|winner|prize|lottery|claim)/i,
      description: 'Prize/lottery scam',
      severity: 'medium',
      examples: ['You won $1000', 'Claim your prize now'],
    },
    {
      id: 'phish-4',
      pattern: /(social security|ssn|irs|tax refund)/i,
      description: 'Government impersonation',
      severity: 'critical',
      examples: ['IRS tax refund pending', 'SSN suspended'],
    },
    {
      id: 'phish-5',
      pattern: /(package|delivery|shipment).*confirm/i,
      description: 'Delivery scam',
      severity: 'high',
      examples: ['Package delivery confirmation required'],
    },
    {
      id: 'phish-6',
      pattern: /(password|pin).*reset/i,
      description: 'Credential theft attempt',
      severity: 'critical',
      examples: ['Reset your password immediately'],
    },
    {
      id: 'phish-7',
      pattern: /\$\d+.*gift card/i,
      description: 'Gift card scam',
      severity: 'high',
      examples: ['$500 gift card waiting'],
    },
  ];

  // Known scam/spam numbers database
  private spamDatabase = new Set<string>([
    '+18005551234', // Example spam numbers
    '+18885559876',
    '+19005554321',
  ]);

  /**
   * Check if number is spam
   */
  async isSpamNumber(number: string): Promise<{
    isSpam: boolean;
    riskScore: number;
    reasons: string[];
    type?: BlockedNumber['type'];
  }> {
    const reasons: string[] = [];
    let riskScore = 0;

    // Check local database
    if (this.spamDatabase.has(number)) {
      reasons.push('Number in spam database');
      riskScore += 80;
    }

    // Check patterns
    for (const pattern of this.spamPatterns) {
      if (pattern.test(number)) {
        reasons.push('Matches spam pattern');
        riskScore += 40;
        break;
      }
    }

    // Check user block list
    const blockedNumbers = await this.getBlockedNumbers();
    const blocked = blockedNumbers.find(b => b.number === number);
    if (blocked) {
      reasons.push('Manually blocked');
      riskScore = 100;
    }

    // Check community reports
    const reports = await this.getNumberReports(number);
    if (reports > 5) {
      reasons.push(`Reported by ${reports} users`);
      riskScore += Math.min(reports * 5, 60);
    }

    // Check international
    if (number.startsWith('+') && !number.startsWith('+1')) {
      const settings = await this.getSettings();
      if (settings.blockInternationalCalls) {
        reasons.push('International number');
        riskScore += 30;
      }
    }

    riskScore = Math.min(riskScore, 100);

    return {
      isSpam: riskScore >= 60,
      riskScore,
      reasons,
      type: blocked?.type || (riskScore >= 80 ? 'spam' : undefined),
    };
  }

  /**
   * Check SMS for phishing/spam
   */
  async checkSMS(from: string, body: string): Promise<SMSMessage> {
    const blockedReasons: string[] = [];
    let riskScore = 0;
    let isPhishing = false;
    let threatType: SMSMessage['threatType'] | undefined;

    // Check sender
    const senderCheck = await this.isSpamNumber(from);
    if (senderCheck.isSpam) {
      blockedReasons.push(...senderCheck.reasons);
      riskScore += senderCheck.riskScore * 0.6;
    }

    // Check for phishing patterns
    for (const pattern of this.phishingPatterns) {
      if (pattern.pattern.test(body)) {
        blockedReasons.push(pattern.description);
        riskScore += pattern.severity === 'critical' ? 40 :
                      pattern.severity === 'high' ? 30 :
                      pattern.severity === 'medium' ? 20 : 10;
        isPhishing = true;
        threatType = 'phishing';
        break;
      }
    }

    // Check for URLs
    const urlPattern = /(https?:\/\/[^\s]+)/gi;
    const urls = body.match(urlPattern);
    if (urls && urls.length > 0) {
      blockedReasons.push('Contains suspicious links');
      riskScore += 25;
    }

    // Check for requests for personal info
    const personalInfoPattern = /(password|ssn|social security|credit card|bank account|pin code)/i;
    if (personalInfoPattern.test(body)) {
      blockedReasons.push('Requests personal information');
      riskScore += 35;
      isPhishing = true;
      threatType = 'phishing';
    }

    // Check for urgency tactics
    const urgencyPattern = /(urgent|immediate|expire|suspend|lock|within 24|act now)/i;
    if (urgencyPattern.test(body)) {
      blockedReasons.push('Uses urgency tactics');
      riskScore += 20;
    }

    // Check for monetary requests
    const moneyPattern = /(\$\d+|pay|payment|fee|charge|wire transfer|gift card)/i;
    if (moneyPattern.test(body)) {
      blockedReasons.push('Requests money or payment');
      riskScore += 25;
      threatType = threatType || 'scam';
    }

    riskScore = Math.min(riskScore, 100);

    const message: SMSMessage = {
      id: `sms-${Date.now()}`,
      from,
      body,
      timestamp: new Date().toISOString(),
      isSpam: riskScore >= 50,
      isPhishing,
      riskScore,
      threatType,
      blockedReasons,
    };

    // Save to blocked messages if spam
    if (message.isSpam) {
      await this.saveBlockedMessage(message);
    }

    return message;
  }

  /**
   * Block a number
   */
  async blockNumber(
    number: string,
    type: BlockedNumber['type'] = 'manual',
    name?: string
  ): Promise<boolean> {
    try {
      const blockedNumbers = await this.getBlockedNumbers();
      
      // Check if already blocked
      const existing = blockedNumbers.find(b => b.number === number);
      if (existing) {
        existing.blockCount++;
        existing.lastAttempt = new Date().toISOString();
      } else {
        const blocked: BlockedNumber = {
          id: `blocked-${Date.now()}`,
          number,
          name,
          type,
          blockedAt: new Date().toISOString(),
          blockCount: 1,
          reportedBy: 0,
        };
        blockedNumbers.unshift(blocked);
      }

      await AsyncStorage.setItem('blocked_numbers', JSON.stringify(blockedNumbers));
      return true;
    } catch (error) {
      console.error('Block number error:', error);
      return false;
    }
  }

  /**
   * Unblock a number
   */
  async unblockNumber(number: string): Promise<boolean> {
    try {
      const blockedNumbers = await this.getBlockedNumbers();
      const filtered = blockedNumbers.filter(b => b.number !== number);
      await AsyncStorage.setItem('blocked_numbers', JSON.stringify(filtered));
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get blocked numbers
   */
  async getBlockedNumbers(): Promise<BlockedNumber[]> {
    try {
      const stored = await AsyncStorage.getItem('blocked_numbers');
      return stored ? JSON.parse(stored) : [];
    } catch (error) {
      return [];
    }
  }

  /**
   * Report spam
   */
  async reportSpam(
    number: string,
    type: 'call' | 'sms',
    category: SpamReport['category'],
    description?: string
  ): Promise<boolean> {
    try {
      const report: SpamReport = {
        id: `report-${Date.now()}`,
        number,
        type,
        category,
        description,
        reportedAt: new Date().toISOString(),
        status: 'pending',
      };

      const reports = await this.getReports();
      reports.unshift(report);
      await AsyncStorage.setItem('spam_reports', JSON.stringify(reports.slice(0, 100)));

      // Auto-block reported number
      await this.blockNumber(number, category);

      return true;
    } catch (error) {
      console.error('Report spam error:', error);
      return false;
    }
  }

  /**
   * Get spam reports
   */
  async getReports(): Promise<SpamReport[]> {
    try {
      const stored = await AsyncStorage.getItem('spam_reports');
      return stored ? JSON.parse(stored) : [];
    } catch (error) {
      return [];
    }
  }

  /**
   * Get number of reports for a specific number
   */
  private async getNumberReports(number: string): Promise<number> {
    const reports = await this.getReports();
    return reports.filter(r => r.number === number).length;
  }

  /**
   * Get protection statistics
   */
  async getProtectionStats(): Promise<ProtectionStats> {
    const blockedNumbers = await this.getBlockedNumbers();
    const blockedMessages = await this.getBlockedMessages();
    
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const thisWeek = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const thisMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    const todayBlocked = blockedMessages.filter(m => 
      new Date(m.timestamp) >= today
    ).length;

    const thisWeekBlocked = blockedMessages.filter(m => 
      new Date(m.timestamp) >= thisWeek
    ).length;

    const thisMonthBlocked = blockedMessages.filter(m => 
      new Date(m.timestamp) >= thisMonth
    ).length;

    const phishingAttempts = blockedMessages.filter(m => m.isPhishing).length;

    // Count by number
    const numberCounts = new Map<string, number>();
    blockedMessages.forEach(m => {
      numberCounts.set(m.from, (numberCounts.get(m.from) || 0) + 1);
    });

    const topSpamSources = Array.from(numberCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([number, count]) => ({
        number,
        count,
        type: 'SMS Spam',
      }));

    return {
      totalBlocked: blockedNumbers.length + blockedMessages.length,
      spamCallsBlocked: blockedNumbers.reduce((sum, b) => sum + b.blockCount, 0),
      spamSMSBlocked: blockedMessages.length,
      phishingAttempts,
      scamPrevented: blockedMessages.filter(m => m.threatType === 'scam').length,
      todayBlocked,
      thisWeekBlocked,
      thisMonthBlocked,
      topSpamSources,
    };
  }

  /**
   * Get blocked messages
   */
  async getBlockedMessages(): Promise<SMSMessage[]> {
    try {
      const stored = await AsyncStorage.getItem('blocked_messages');
      return stored ? JSON.parse(stored) : [];
    } catch (error) {
      return [];
    }
  }

  /**
   * Save blocked message
   */
  private async saveBlockedMessage(message: SMSMessage): Promise<void> {
    try {
      const messages = await this.getBlockedMessages();
      messages.unshift(message);
      await AsyncStorage.setItem('blocked_messages', JSON.stringify(messages.slice(0, 500)));
    } catch (error) {
      console.error('Save blocked message error:', error);
    }
  }

  /**
   * Get protection settings
   */
  async getSettings(): Promise<ProtectionSettings> {
    try {
      const stored = await AsyncStorage.getItem('sms_call_protection_settings');
      return stored ? JSON.parse(stored) : this.getDefaultSettings();
    } catch (error) {
      return this.getDefaultSettings();
    }
  }

  /**
   * Update protection settings
   */
  async updateSettings(settings: ProtectionSettings): Promise<boolean> {
    try {
      await AsyncStorage.setItem('sms_call_protection_settings', JSON.stringify(settings));
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get default settings
   */
  private getDefaultSettings(): ProtectionSettings {
    return {
      blockSpamCalls: true,
      blockSpamSMS: true,
      blockInternationalCalls: false,
      blockHiddenNumbers: false,
      detectPhishing: true,
      autoReportSpam: true,
      silenceUnknownCallers: false,
      allowContactsOnly: false,
      customBlockList: [],
      customAllowList: [],
    };
  }

  /**
   * Get spam database info
   */
  async getDatabaseInfo(): Promise<SpamDatabase> {
    return {
      version: '2024.11.09',
      lastUpdated: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
      spamNumbers: this.spamDatabase.size,
      scamPatterns: this.phishingPatterns.length,
      communityReports: (await this.getReports()).length,
    };
  }

  /**
   * Update spam database
   */
  async updateDatabase(): Promise<boolean> {
    try {
      // In production, would fetch from server
      // For now, simulate update
      await new Promise(resolve => setTimeout(resolve, 1000));
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Test SMS for phishing (utility method)
   */
  testSMS(body: string): { isPhishing: boolean; patterns: PhishingPattern[] } {
    const matchedPatterns: PhishingPattern[] = [];
    
    for (const pattern of this.phishingPatterns) {
      if (pattern.pattern.test(body)) {
        matchedPatterns.push(pattern);
      }
    }

    return {
      isPhishing: matchedPatterns.length > 0,
      patterns: matchedPatterns,
    };
  }

  /**
   * Get phishing patterns for educational purposes
   */
  getPhishingPatterns(): PhishingPattern[] {
    return this.phishingPatterns;
  }

  /**
   * Format phone number
   */
  formatPhoneNumber(number: string): string {
    const cleaned = number.replace(/\D/g, '');
    
    if (cleaned.length === 10) {
      return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`;
    } else if (cleaned.length === 11 && cleaned[0] === '1') {
      return `+1 (${cleaned.slice(1, 4)}) ${cleaned.slice(4, 7)}-${cleaned.slice(7)}`;
    }
    
    return number;
  }

  /**
   * Get risk level color
   */
  getRiskColor(riskScore: number): string {
    if (riskScore >= 80) return '#d32f2f';
    if (riskScore >= 60) return '#f44336';
    if (riskScore >= 40) return '#ff9800';
    if (riskScore >= 20) return '#ffc107';
    return '#4caf50';
  }
}

export const SMSCallProtectionService = new SMSCallProtectionServiceClass();
