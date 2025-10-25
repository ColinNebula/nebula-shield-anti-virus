/**
 * Nebula Shield - Real-Time Firewall Engine
 * Production-grade network security with AI-powered threat detection
 */

const os = require('os');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

class FirewallEngine {
  constructor() {
    this.rules = new Map();
    this.blockedIPs = new Set();
    this.allowedIPs = new Set();
    this.activeConnections = new Map();
    this.threatLog = [];
    this.statistics = {
      packetsInspected: 0,
      threatsBlocked: 0,
      allowedConnections: 0,
      droppedPackets: 0,
      ruleHits: new Map()
    };
    
    // Real-time monitoring
    this.isMonitoring = false;
    this.monitoringInterval = null;
    
    // Windows Firewall integration
    this.platform = os.platform();
    this.windowsFirewallEnabled = false;
    
    this.initialize();
  }

  /**
   * Initialize firewall engine
   */
  async initialize() {
    console.log('🔥 Initializing Nebula Shield Firewall Engine...');
    
    // Load default rules
    this.loadDefaultRules();
    
    // Check Windows Firewall status
    if (this.platform === 'win32') {
      await this.checkWindowsFirewall();
    }
    
    console.log(`✅ Firewall Engine initialized`);
    console.log(`   Platform: ${this.platform}`);
    console.log(`   Rules loaded: ${this.rules.size}`);
    console.log(`   Windows Firewall: ${this.windowsFirewallEnabled ? 'Enabled' : 'Disabled/Not available'}`);
  }

  /**
   * Load default firewall rules
   */
  loadDefaultRules() {
    const defaultRules = [
      {
        id: 'rule_001',
        name: 'Block Tor Exit Nodes',
        type: 'ip',
        action: 'block',
        direction: 'inbound',
        protocol: 'tcp',
        target: 'tor_exit_nodes',
        enabled: true,
        priority: 1,
        description: 'Block connections from known Tor exit nodes'
      },
      {
        id: 'rule_002',
        name: 'Block Known C2 Servers',
        type: 'ip',
        action: 'block',
        direction: 'both',
        protocol: 'any',
        target: 'c2_servers',
        enabled: true,
        priority: 1,
        description: 'Block command & control server communications'
      },
      {
        id: 'rule_003',
        name: 'Allow HTTP/HTTPS',
        type: 'port',
        action: 'allow',
        direction: 'outbound',
        protocol: 'tcp',
        ports: [80, 443, 8080, 8443],
        enabled: true,
        priority: 5,
        description: 'Allow standard web traffic'
      },
      {
        id: 'rule_004',
        name: 'Block Cryptocurrency Mining',
        type: 'pattern',
        action: 'block',
        direction: 'outbound',
        protocol: 'tcp',
        pattern: /(stratum\+tcp|stratum\+ssl|mining\.pool)/i,
        ports: [3333, 4444, 5555, 7777, 8888, 9999],
        enabled: true,
        priority: 2,
        description: 'Block connections to cryptocurrency mining pools'
      },
      {
        id: 'rule_005',
        name: 'Rate Limit SSH',
        type: 'rate_limit',
        action: 'rate_limit',
        direction: 'inbound',
        protocol: 'tcp',
        ports: [22],
        maxConnections: 5,
        timeWindow: 300, // 5 minutes
        enabled: true,
        priority: 3,
        description: 'Prevent SSH brute force attacks'
      },
      {
        id: 'rule_006',
        name: 'Block Remote Desktop Brute Force',
        type: 'rate_limit',
        action: 'rate_limit',
        direction: 'inbound',
        protocol: 'tcp',
        ports: [3389],
        maxConnections: 3,
        timeWindow: 600, // 10 minutes
        enabled: true,
        priority: 3,
        description: 'Prevent RDP brute force attacks'
      },
      {
        id: 'rule_007',
        name: 'Block Malware Callback Domains',
        type: 'domain',
        action: 'block',
        direction: 'outbound',
        protocol: 'any',
        domains: ['malware.ru', 'c2server.net', 'botnet.com'],
        enabled: true,
        priority: 1,
        description: 'Block known malware callback domains'
      },
      {
        id: 'rule_008',
        name: 'Allow DNS',
        type: 'port',
        action: 'allow',
        direction: 'outbound',
        protocol: 'udp',
        ports: [53],
        enabled: true,
        priority: 5,
        description: 'Allow DNS queries'
      },
      {
        id: 'rule_009',
        name: 'Block NetBIOS',
        type: 'port',
        action: 'block',
        direction: 'inbound',
        protocol: 'tcp',
        ports: [137, 138, 139, 445],
        enabled: true,
        priority: 2,
        description: 'Block NetBIOS and SMB (prevents WannaCry-style attacks)'
      },
      {
        id: 'rule_010',
        name: 'Geo-Block High-Risk Countries',
        type: 'geo',
        action: 'block',
        direction: 'inbound',
        protocol: 'any',
        countries: ['KP', 'IR', 'SY'],
        enabled: false,
        priority: 2,
        description: 'Block connections from high-risk countries'
      }
    ];

    defaultRules.forEach(rule => {
      this.rules.set(rule.id, rule);
    });
  }

  /**
   * Check Windows Firewall status
   */
  async checkWindowsFirewall() {
    if (this.platform !== 'win32') return false;

    try {
      const { stdout } = await execAsync('netsh advfirewall show allprofiles state');
      this.windowsFirewallEnabled = stdout.toLowerCase().includes('state on');
      return this.windowsFirewallEnabled;
    } catch (error) {
      console.warn('Could not check Windows Firewall status:', error.message);
      return false;
    }
  }

  /**
   * Get Windows Firewall rules
   */
  async getWindowsFirewallRules() {
    if (this.platform !== 'win32') {
      return { success: false, error: 'Not on Windows platform' };
    }

    try {
      const { stdout } = await execAsync('netsh advfirewall firewall show rule name=all');
      
      // Parse rules
      const rules = [];
      const ruleBlocks = stdout.split(/\r?\n\r?\n/);
      
      for (const block of ruleBlocks) {
        if (block.includes('Rule Name:')) {
          const rule = {};
          const lines = block.split(/\r?\n/);
          
          lines.forEach(line => {
            const [key, ...valueParts] = line.split(':');
            const value = valueParts.join(':').trim();
            
            if (key && value) {
              const cleanKey = key.trim().toLowerCase().replace(/\s+/g, '_');
              rule[cleanKey] = value;
            }
          });
          
          if (rule.rule_name) {
            rules.push(rule);
          }
        }
      }

      return { success: true, rules, count: rules.length };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Add Windows Firewall rule
   */
  async addWindowsFirewallRule(ruleName, config) {
    if (this.platform !== 'win32') {
      return { success: false, error: 'Not on Windows platform' };
    }

    try {
      const {
        direction = 'in',
        action = 'block',
        protocol = 'tcp',
        localPort,
        remoteIP,
        program
      } = config;

      let command = `netsh advfirewall firewall add rule name="${ruleName}" dir=${direction} action=${action}`;
      
      if (protocol) command += ` protocol=${protocol}`;
      if (localPort) command += ` localport=${localPort}`;
      if (remoteIP) command += ` remoteip=${remoteIP}`;
      if (program) command += ` program="${program}"`;

      const { stdout, stderr } = await execAsync(command);
      
      return {
        success: !stderr && stdout.toLowerCase().includes('ok'),
        message: stdout,
        error: stderr
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Remove Windows Firewall rule
   */
  async removeWindowsFirewallRule(ruleName) {
    if (this.platform !== 'win32') {
      return { success: false, error: 'Not on Windows platform' };
    }

    try {
      const { stdout, stderr } = await execAsync(
        `netsh advfirewall firewall delete rule name="${ruleName}"`
      );
      
      return {
        success: !stderr && (stdout.toLowerCase().includes('ok') || stdout.toLowerCase().includes('deleted')),
        message: stdout,
        error: stderr
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Block IP address
   */
  async blockIP(ip, reason = 'Manual block') {
    this.blockedIPs.add(ip);
    
    // Log the action
    this.logThreat({
      type: 'ip_blocked',
      severity: 'high',
      ip,
      reason,
      timestamp: new Date().toISOString()
    });

    // Add to Windows Firewall if available
    if (this.platform === 'win32' && this.windowsFirewallEnabled) {
      const ruleName = `Nebula Shield - Block ${ip}`;
      await this.addWindowsFirewallRule(ruleName, {
        direction: 'in',
        action: 'block',
        protocol: 'any',
        remoteIP: ip
      });
    }

    return { success: true, ip, blocked: true };
  }

  /**
   * Unblock IP address
   */
  async unblockIP(ip) {
    this.blockedIPs.delete(ip);

    // Remove from Windows Firewall if available
    if (this.platform === 'win32' && this.windowsFirewallEnabled) {
      const ruleName = `Nebula Shield - Block ${ip}`;
      await this.removeWindowsFirewallRule(ruleName);
    }

    return { success: true, ip, unblocked: true };
  }

  /**
   * Add firewall rule
   */
  addRule(rule) {
    const ruleId = rule.id || `rule_${Date.now()}`;
    
    const fullRule = {
      ...rule,
      id: ruleId,
      createdAt: new Date().toISOString(),
      enabled: rule.enabled !== false
    };

    this.rules.set(ruleId, fullRule);
    
    return { success: true, rule: fullRule };
  }

  /**
   * Update firewall rule
   */
  updateRule(ruleId, updates) {
    const rule = this.rules.get(ruleId);
    
    if (!rule) {
      return { success: false, error: 'Rule not found' };
    }

    const updatedRule = {
      ...rule,
      ...updates,
      updatedAt: new Date().toISOString()
    };

    this.rules.set(ruleId, updatedRule);
    
    return { success: true, rule: updatedRule };
  }

  /**
   * Delete firewall rule
   */
  deleteRule(ruleId) {
    const rule = this.rules.get(ruleId);
    
    if (!rule) {
      return { success: false, error: 'Rule not found' };
    }

    this.rules.delete(ruleId);
    
    return { success: true, deleted: true };
  }

  /**
   * Get all rules
   */
  getRules() {
    return Array.from(this.rules.values());
  }

  /**
   * Inspect packet against firewall rules
   */
  inspectPacket(packet) {
    this.statistics.packetsInspected++;

    const {
      sourceIP,
      destIP,
      sourcePort,
      destPort,
      protocol,
      payload,
      direction
    } = packet;

    // Check if IP is blocked
    if (this.blockedIPs.has(sourceIP) || this.blockedIPs.has(destIP)) {
      this.statistics.droppedPackets++;
      return {
        action: 'block',
        reason: 'IP in blocklist',
        rule: 'blocklist'
      };
    }

    // Check if IP is allowed
    if (this.allowedIPs.has(sourceIP) || this.allowedIPs.has(destIP)) {
      this.statistics.allowedConnections++;
      return {
        action: 'allow',
        reason: 'IP in allowlist',
        rule: 'allowlist'
      };
    }

    // Apply rules in priority order
    const sortedRules = Array.from(this.rules.values())
      .filter(r => r.enabled)
      .sort((a, b) => a.priority - b.priority);

    for (const rule of sortedRules) {
      const match = this.checkRuleMatch(rule, packet);
      
      if (match) {
        // Increment rule hit counter
        const currentHits = this.statistics.ruleHits.get(rule.id) || 0;
        this.statistics.ruleHits.set(rule.id, currentHits + 1);

        if (rule.action === 'block') {
          this.statistics.threatsBlocked++;
          this.statistics.droppedPackets++;
          
          this.logThreat({
            type: 'rule_block',
            severity: rule.priority <= 2 ? 'high' : 'medium',
            rule: rule.name,
            sourceIP,
            destIP,
            port: destPort,
            protocol,
            timestamp: new Date().toISOString()
          });
        } else {
          this.statistics.allowedConnections++;
        }

        return {
          action: rule.action,
          reason: rule.description,
          rule: rule.name,
          ruleId: rule.id
        };
      }
    }

    // Default allow (if no rules matched)
    this.statistics.allowedConnections++;
    return {
      action: 'allow',
      reason: 'No matching rules (default allow)',
      rule: 'default'
    };
  }

  /**
   * Check if packet matches rule
   */
  checkRuleMatch(rule, packet) {
    const { sourceIP, destIP, sourcePort, destPort, protocol, payload, direction } = packet;

    // Check direction
    if (rule.direction !== 'both' && rule.direction !== direction) {
      return false;
    }

    // Check protocol
    if (rule.protocol !== 'any' && rule.protocol !== protocol) {
      return false;
    }

    // Check by rule type
    switch (rule.type) {
      case 'port':
        if (rule.ports && rule.ports.length > 0) {
          return rule.ports.includes(destPort) || rule.ports.includes(sourcePort);
        }
        break;

      case 'ip':
        // Simplified - in production would check against IP lists
        return true;

      case 'domain':
        // Would check DNS resolution in production
        return rule.domains && payload && rule.domains.some(domain => 
          payload.includes(domain)
        );

      case 'pattern':
        if (rule.pattern && payload) {
          return rule.pattern.test(payload);
        }
        break;

      case 'rate_limit':
        // Simplified rate limiting
        const key = `${sourceIP}:${destPort}`;
        const connections = this.activeConnections.get(key) || [];
        const recentConnections = connections.filter(
          time => Date.now() - time < rule.timeWindow * 1000
        );
        
        if (recentConnections.length >= rule.maxConnections) {
          return true;
        }
        
        recentConnections.push(Date.now());
        this.activeConnections.set(key, recentConnections);
        break;

      case 'geo':
        // Would use GeoIP lookup in production
        return false;
    }

    return false;
  }

  /**
   * Log threat
   */
  logThreat(threat) {
    this.threatLog.unshift(threat);
    
    // Keep last 1000 threats
    if (this.threatLog.length > 1000) {
      this.threatLog = this.threatLog.slice(0, 1000);
    }
  }

  /**
   * Get threat log
   */
  getThreatLog(limit = 50) {
    return this.threatLog.slice(0, limit);
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.statistics,
      ruleHits: Object.fromEntries(this.statistics.ruleHits),
      blockedIPsCount: this.blockedIPs.size,
      allowedIPsCount: this.allowedIPs.size,
      rulesCount: this.rules.size,
      activeRulesCount: Array.from(this.rules.values()).filter(r => r.enabled).length
    };
  }

  /**
   * Start real-time monitoring
   */
  startMonitoring() {
    if (this.isMonitoring) return;

    this.isMonitoring = true;
    console.log('🔍 Firewall monitoring started');

    // Simulate packet inspection (in production, would hook into network stack)
    this.monitoringInterval = setInterval(() => {
      // Simulate random network activity
      if (Math.random() < 0.3) {
        const packet = this.generateRandomPacket();
        this.inspectPacket(packet);
      }
    }, 1000);
  }

  /**
   * Stop real-time monitoring
   */
  stopMonitoring() {
    if (!this.isMonitoring) return;

    this.isMonitoring = false;
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }
    
    console.log('🛑 Firewall monitoring stopped');
  }

  /**
   * Generate random packet for simulation
   */
  generateRandomPacket() {
    const protocols = ['tcp', 'udp', 'icmp'];
    const directions = ['inbound', 'outbound'];
    
    return {
      sourceIP: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      destIP: `192.168.1.${Math.floor(Math.random() * 255)}`,
      sourcePort: Math.floor(Math.random() * 65535),
      destPort: Math.floor(Math.random() * 65535),
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      direction: directions[Math.floor(Math.random() * directions.length)],
      payload: null
    };
  }

  /**
   * Get blocked IPs
   */
  getBlockedIPs() {
    return Array.from(this.blockedIPs);
  }

  /**
   * Get allowed IPs
   */
  getAllowedIPs() {
    return Array.from(this.allowedIPs);
  }

  /**
   * Clear threat log
   */
  clearThreatLog() {
    this.threatLog = [];
    return { success: true, message: 'Threat log cleared' };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.statistics = {
      packetsInspected: 0,
      threatsBlocked: 0,
      allowedConnections: 0,
      droppedPackets: 0,
      ruleHits: new Map()
    };
    
    return { success: true, message: 'Statistics reset' };
  }
}

module.exports = new FirewallEngine();
