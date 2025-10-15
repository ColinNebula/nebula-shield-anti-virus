/**
 * YARA Rule Engine for Nebula Shield
 * Provides advanced pattern-based malware detection using YARA-like rules
 * 
 * Features:
 * - Custom rule compilation
 * - String and hex pattern matching
 * - Condition evaluation
 * - Meta information tracking
 * - Rule import/export
 */

class YaraEngine {
  constructor() {
    this.rules = new Map();
    this.compiledRules = new Map();
    this.matchHistory = [];
    this.loadDefaultRules();
  }

  /**
   * Parse and compile a YARA rule
   * @param {string} ruleText - YARA rule text
   * @returns {Object} Compiled rule object
   */
  compileRule(ruleText) {
    try {
      const rule = this.parseYaraRule(ruleText);
      this.compiledRules.set(rule.name, rule);
      return { success: true, rule: rule.name };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Parse YARA rule syntax
   * @param {string} ruleText - Raw YARA rule
   * @returns {Object} Parsed rule structure
   */
  parseYaraRule(ruleText) {
    const nameMatch = ruleText.match(/rule\s+(\w+)/);
    if (!nameMatch) throw new Error('Invalid rule: missing rule name');
    
    const name = nameMatch[1];
    const meta = this.extractMeta(ruleText);
    const strings = this.extractStrings(ruleText);
    const condition = this.extractCondition(ruleText);
    
    return {
      name,
      meta,
      strings,
      condition,
      rawRule: ruleText,
      compiledAt: new Date().toISOString()
    };
  }

  /**
   * Extract metadata from rule
   */
  extractMeta(ruleText) {
    const meta = {};
    const metaSection = ruleText.match(/meta:\s*\n([\s\S]*?)\n\s*strings:/);
    
    if (metaSection) {
      const lines = metaSection[1].split('\n');
      lines.forEach(line => {
        const match = line.match(/(\w+)\s*=\s*"([^"]+)"/);
        if (match) {
          meta[match[1]] = match[2];
        }
      });
    }
    
    return meta;
  }

  /**
   * Extract string patterns from rule
   */
  extractStrings(ruleText) {
    const strings = {};
    const stringsSection = ruleText.match(/strings:\s*\n([\s\S]*?)\n\s*condition:/);
    
    if (stringsSection) {
      const lines = stringsSection[1].split('\n');
      lines.forEach(line => {
        // String pattern: $var = "string"
        const strMatch = line.match(/\$(\w+)\s*=\s*"([^"]+)"/);
        if (strMatch) {
          strings[strMatch[1]] = {
            type: 'text',
            value: strMatch[2],
            modifiers: this.extractModifiers(line)
          };
          return;
        }
        
        // Hex pattern: $var = { HE X }
        const hexMatch = line.match(/\$(\w+)\s*=\s*\{\s*([0-9A-Fa-f\s\?\[\]]+)\s*\}/);
        if (hexMatch) {
          strings[hexMatch[1]] = {
            type: 'hex',
            value: hexMatch[2].replace(/\s+/g, ''),
            modifiers: this.extractModifiers(line)
          };
          return;
        }
        
        // Regex pattern: $var = /regex/
        const regexMatch = line.match(/\$(\w+)\s*=\s*\/([^\/]+)\//);
        if (regexMatch) {
          strings[regexMatch[1]] = {
            type: 'regex',
            value: regexMatch[2],
            modifiers: this.extractModifiers(line)
          };
        }
      });
    }
    
    return strings;
  }

  /**
   * Extract pattern modifiers (nocase, wide, ascii, fullword)
   */
  extractModifiers(line) {
    const modifiers = {};
    if (line.includes('nocase')) modifiers.nocase = true;
    if (line.includes('wide')) modifiers.wide = true;
    if (line.includes('ascii')) modifiers.ascii = true;
    if (line.includes('fullword')) modifiers.fullword = true;
    return modifiers;
  }

  /**
   * Extract condition from rule
   */
  extractCondition(ruleText) {
    const condMatch = ruleText.match(/condition:\s*\n\s*(.+)/);
    return condMatch ? condMatch[1].trim() : 'any of them';
  }

  /**
   * Scan content against all compiled rules
   * @param {string|Buffer} content - Content to scan
   * @param {string} fileName - Name of file being scanned
   * @returns {Array} Array of matches
   */
  scanContent(content, fileName = 'unknown') {
    const matches = [];
    const contentStr = content.toString();
    
    for (const [ruleName, rule] of this.compiledRules) {
      const result = this.evaluateRule(rule, contentStr, fileName);
      if (result.matched) {
        matches.push({
          rule: ruleName,
          meta: rule.meta,
          matchedStrings: result.matchedStrings,
          fileName,
          timestamp: new Date().toISOString()
        });
      }
    }
    
    this.matchHistory.push(...matches);
    return matches;
  }

  /**
   * Evaluate a rule against content
   */
  evaluateRule(rule, content, fileName) {
    const matchedStrings = [];
    
    // Check each string pattern
    for (const [varName, pattern] of Object.entries(rule.strings)) {
      const matches = this.matchPattern(pattern, content);
      if (matches.length > 0) {
        matchedStrings.push({
          variable: varName,
          pattern: pattern.value,
          type: pattern.type,
          count: matches.length,
          positions: matches
        });
      }
    }
    
    // Evaluate condition
    const matched = this.evaluateCondition(rule.condition, matchedStrings, rule.strings);
    
    return { matched, matchedStrings };
  }

  /**
   * Match a pattern against content
   */
  matchPattern(pattern, content) {
    const matches = [];
    let searchContent = content;
    
    // Apply modifiers
    if (pattern.modifiers.nocase) {
      searchContent = content.toLowerCase();
      pattern.value = pattern.value.toLowerCase();
    }
    
    switch (pattern.type) {
      case 'text':
        let index = 0;
        while ((index = searchContent.indexOf(pattern.value, index)) !== -1) {
          matches.push({ offset: index, length: pattern.value.length });
          index += pattern.value.length;
        }
        break;
        
      case 'hex':
        const hexPattern = this.hexToRegex(pattern.value);
        const hexMatches = searchContent.matchAll(hexPattern);
        for (const match of hexMatches) {
          matches.push({ offset: match.index, length: match[0].length });
        }
        break;
        
      case 'regex':
        const regex = new RegExp(pattern.value, pattern.modifiers.nocase ? 'gi' : 'g');
        const regexMatches = searchContent.matchAll(regex);
        for (const match of regexMatches) {
          matches.push({ offset: match.index, length: match[0].length });
        }
        break;
    }
    
    return matches;
  }

  /**
   * Convert hex pattern to regex
   */
  hexToRegex(hexPattern) {
    // Convert hex bytes to regex pattern
    // E.g., "4D5A" -> /\x4D\x5A/
    const pattern = hexPattern.replace(/([0-9A-Fa-f]{2})/g, '\\x$1');
    return new RegExp(pattern, 'g');
  }

  /**
   * Evaluate rule condition
   */
  evaluateCondition(condition, matchedStrings, allStrings) {
    // Simple condition evaluation
    if (condition === 'any of them') {
      return matchedStrings.length > 0;
    }
    
    if (condition === 'all of them') {
      return matchedStrings.length === Object.keys(allStrings).length;
    }
    
    // Numeric conditions: "2 of them", "3 of them"
    const numMatch = condition.match(/(\d+)\s+of\s+them/);
    if (numMatch) {
      const required = parseInt(numMatch[1]);
      return matchedStrings.length >= required;
    }
    
    // Specific variable conditions: "$a and $b"
    const varPattern = /\$(\w+)/g;
    const requiredVars = [];
    let match;
    while ((match = varPattern.exec(condition)) !== null) {
      requiredVars.push(match[1]);
    }
    
    if (requiredVars.length > 0) {
      const matchedVars = matchedStrings.map(m => m.variable);
      
      if (condition.includes(' and ')) {
        return requiredVars.every(v => matchedVars.includes(v));
      }
      
      if (condition.includes(' or ')) {
        return requiredVars.some(v => matchedVars.includes(v));
      }
    }
    
    return matchedStrings.length > 0;
  }

  /**
   * Load default YARA rules
   */
  loadDefaultRules() {
    const defaultRules = [
      // EICAR Test Rule
      `rule EICAR_Test_File {
        meta:
          description = "EICAR antivirus test file"
          author = "Nebula Shield"
          severity = "test"
          reference = "https://www.eicar.org/"
        strings:
          $eicar = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        condition:
          $eicar
      }`,
      
      // WannaCry Ransomware
      `rule WannaCry_Ransomware {
        meta:
          description = "WannaCry ransomware detection"
          author = "Nebula Shield"
          severity = "critical"
          malware_family = "Ransomware"
        strings:
          $s1 = "WNcry@2ol7" nocase
          $s2 = "WANACRY!" nocase
          $s3 = "tasksche.exe"
          $s4 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
        condition:
          2 of them
      }`,
      
      // Emotet Trojan
      `rule Emotet_Banking_Trojan {
        meta:
          description = "Emotet banking trojan"
          author = "Nebula Shield"
          severity = "critical"
          malware_family = "Trojan"
        strings:
          $s1 = "emotet" nocase
          $s2 = "heodo" nocase
          $s3 = { 8B 45 ?? 83 C0 04 89 45 ?? 8B 4D ?? 3B 4D ?? 73 }
        condition:
          any of them
      }`,
      
      // Cobalt Strike Beacon
      `rule CobaltStrike_Beacon {
        meta:
          description = "Cobalt Strike beacon detection"
          author = "Nebula Shield"
          severity = "critical"
          malware_family = "Framework"
        strings:
          $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
          $s2 = "cobaltstrike" nocase
          $s3 = "beacon.dll"
          $s4 = { 69 68 C0 00 00 00 6A 00 68 58 A4 53 E5 }
        condition:
          2 of them
      }`,
      
      // Mimikatz Credential Dumper
      `rule Mimikatz_Credential_Dumper {
        meta:
          description = "Mimikatz credential dumping tool"
          author = "Nebula Shield"
          severity = "critical"
          malware_family = "Stealer"
        strings:
          $s1 = "sekurlsa::logonpasswords"
          $s2 = "lsadump::sam"
          $s3 = "privilege::debug"
          $s4 = "mimikatz" nocase
          $s5 = "gentilkiwi"
        condition:
          2 of them
      }`,
      
      // PowerShell Empire
      `rule PowerShell_Empire {
        meta:
          description = "PowerShell Empire post-exploitation framework"
          author = "Nebula Shield"
          severity = "critical"
          malware_family = "Framework"
        strings:
          $s1 = "Invoke-Empire"
          $s2 = "Invoke-Mimikatz"
          $s3 = "PowerShellEmpire"
          $s4 = "Get-Keystrokes"
          $s5 = "Invoke-Shellcode"
        condition:
          2 of them
      }`,
      
      // Meterpreter
      `rule Meterpreter_Payload {
        meta:
          description = "Metasploit Meterpreter payload"
          author = "Nebula Shield"
          severity = "critical"
          malware_family = "Backdoor"
        strings:
          $s1 = "meterpreter" nocase
          $s2 = "ReflectiveLoader"
          $s3 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }
          $s4 = "stdapi"
        condition:
          2 of them
      }`,
      
      // Suspicious PowerShell
      `rule Suspicious_PowerShell_Script {
        meta:
          description = "Suspicious PowerShell script indicators"
          author = "Nebula Shield"
          severity = "high"
          malware_family = "Script"
        strings:
          $s1 = "Invoke-Expression" nocase
          $s2 = "DownloadString" nocase
          $s3 = "FromBase64String" nocase
          $s4 = "-EncodedCommand" nocase
          $s5 = "Net.WebClient" nocase
          $s6 = "System.Reflection.Assembly"
        condition:
          3 of them
      }`,
      
      // PHP Web Shell
      `rule PHP_Web_Shell {
        meta:
          description = "PHP web shell detection"
          author = "Nebula Shield"
          severity = "critical"
          malware_family = "WebShell"
        strings:
          $s1 = "eval($_POST" nocase
          $s2 = "eval($_GET" nocase
          $s3 = "shell_exec" nocase
          $s4 = "system($_" nocase
          $s5 = "passthru($_" nocase
          $s6 = "c99shell" nocase
        condition:
          2 of them
      }`,
      
      // Ransomware Generic
      `rule Ransomware_Generic {
        meta:
          description = "Generic ransomware indicators"
          author = "Nebula Shield"
          severity = "critical"
          malware_family = "Ransomware"
        strings:
          $s1 = "DECRYPT" nocase
          $s2 = "RANSOM" nocase
          $s3 = "BITCOIN" nocase
          $s4 = ".locked"
          $s5 = ".encrypted"
          $s6 = "YOUR FILES"
          $s7 = "PAY NOW"
        condition:
          3 of them
      }`,
      
      // Keylogger
      `rule Generic_Keylogger {
        meta:
          description = "Generic keylogger detection"
          author = "Nebula Shield"
          severity = "high"
          malware_family = "Spyware"
        strings:
          $s1 = "GetAsyncKeyState" nocase
          $s2 = "SetWindowsHookEx" nocase
          $s3 = "WH_KEYBOARD"
          $s4 = "keylogger" nocase
          $s5 = "keystroke" nocase
        condition:
          2 of them
      }`,
      
      // Cryptocurrency Miner
      `rule Cryptocurrency_Miner {
        meta:
          description = "Cryptocurrency mining malware"
          author = "Nebula Shield"
          severity = "medium"
          malware_family = "Miner"
        strings:
          $s1 = "stratum+tcp" nocase
          $s2 = "xmrig" nocase
          $s3 = "monero" nocase
          $s4 = "cryptonight" nocase
          $s5 = "pool.minexmr" nocase
        condition:
          2 of them
      }`
    ];
    
    defaultRules.forEach(rule => {
      this.compileRule(rule);
    });
  }

  /**
   * Import rules from file
   */
  importRules(rulesText) {
    const rules = rulesText.split(/(?=rule\s+\w+)/);
    const results = { success: 0, failed: 0, errors: [] };
    
    rules.forEach(rule => {
      if (rule.trim()) {
        const result = this.compileRule(rule);
        if (result.success) {
          results.success++;
        } else {
          results.failed++;
          results.errors.push(result.error);
        }
      }
    });
    
    return results;
  }

  /**
   * Export all rules
   */
  exportRules() {
    const rules = [];
    for (const rule of this.compiledRules.values()) {
      rules.push(rule.rawRule);
    }
    return rules.join('\n\n');
  }

  /**
   * Get rule statistics
   */
  getStats() {
    return {
      totalRules: this.compiledRules.size,
      totalMatches: this.matchHistory.length,
      rulesByFamily: this.getRulesByFamily(),
      recentMatches: this.matchHistory.slice(-10)
    };
  }

  /**
   * Group rules by malware family
   */
  getRulesByFamily() {
    const families = {};
    for (const rule of this.compiledRules.values()) {
      const family = rule.meta.malware_family || 'Unknown';
      families[family] = (families[family] || 0) + 1;
    }
    return families;
  }

  /**
   * Clear match history
   */
  clearHistory() {
    this.matchHistory = [];
  }

  /**
   * Get rule by name
   */
  getRule(name) {
    return this.compiledRules.get(name);
  }

  /**
   * Delete rule
   */
  deleteRule(name) {
    return this.compiledRules.delete(name);
  }

  /**
   * List all rules
   */
  listRules() {
    return Array.from(this.compiledRules.keys());
  }
}

// Export singleton instance
const yaraEngine = new YaraEngine();
export default yaraEngine;
