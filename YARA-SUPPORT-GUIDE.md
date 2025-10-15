# 🔍 YARA Rule Support Guide
## Nebula Shield Anti-Virus

**Version:** 1.0.0  
**Last Updated:** October 13, 2025

---

## 📋 Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [YARA Syntax Guide](#yara-syntax-guide)
4. [Default Rules](#default-rules)
5. [Creating Custom Rules](#creating-custom-rules)
6. [Advanced Features](#advanced-features)
7. [Integration](#integration)
8. [Best Practices](#best-practices)
9. [Examples](#examples)
10. [API Reference](#api-reference)

---

## 🎯 Introduction

YARA is a pattern-matching Swiss Army knife for malware researchers. Nebula Shield now includes a **JavaScript implementation of YARA** that supports:

✅ **String Patterns** - Text-based detection  
✅ **Hex Patterns** - Binary signatures  
✅ **Regex Patterns** - Complex pattern matching  
✅ **Metadata** - Rule information and attribution  
✅ **Conditions** - Logical evaluation of matches  
✅ **Modifiers** - Case-insensitive, wide-char, fullword  
✅ **Import/Export** - Share rules with the community

---

## 🚀 Quick Start

### Basic Usage

```javascript
import yaraEngine from './services/yaraEngine';

// Scan content
const content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const matches = yaraEngine.scanContent(content, 'test.txt');

if (matches.length > 0) {
  console.log('Threats detected!');
  matches.forEach(match => {
    console.log(`Rule: ${match.rule}`);
    console.log(`Description: ${match.meta.description}`);
  });
}
```

### Import Custom Rules

```javascript
const customRule = `
rule My_Custom_Malware {
  meta:
    description = "My custom malware detection"
    author = "Your Name"
    severity = "high"
  strings:
    $s1 = "malicious_string"
    $s2 = { 4D 5A 90 00 }
  condition:
    all of them
}
`;

yaraEngine.compileRule(customRule);
```

---

## 📖 YARA Syntax Guide

### Rule Structure

```yara
rule RuleName {
  meta:
    key = "value"
    
  strings:
    $variable = "pattern"
    
  condition:
    expression
}
```

### Components

#### 1. **Meta Section** (Optional)
Provides metadata about the rule:

```yara
meta:
  description = "Brief description of the threat"
  author = "Your name"
  severity = "critical|high|medium|low"
  malware_family = "Trojan|Ransomware|Worm|etc"
  reference = "URL or CVE"
  date = "2025-10-13"
```

#### 2. **Strings Section**
Define patterns to search for:

**Text Strings:**
```yara
strings:
  $text1 = "malware"
  $text2 = "suspicious" nocase
  $text3 = "exact word" fullword
```

**Hex Patterns:**
```yara
strings:
  $hex1 = { 4D 5A 90 00 }
  $hex2 = { 4D 5A ?? ?? }  // ?? = wildcard byte
  $hex3 = { 4D 5A [2-4] 50 45 }  // [n-m] = n to m bytes
```

**Regex Patterns:**
```yara
strings:
  $regex1 = /malware|trojan|virus/
  $regex2 = /192\.168\.\d{1,3}\.\d{1,3}/
```

**Modifiers:**
- `nocase` - Case-insensitive matching
- `wide` - UTF-16 encoded strings
- `ascii` - ASCII strings (default)
- `fullword` - Match complete words only

#### 3. **Condition Section**
Logical expression to evaluate matches:

```yara
condition:
  any of them          // At least one string matches
  all of them          // All strings match
  2 of them            // At least 2 strings match
  $s1 and $s2          // Both $s1 and $s2 match
  $s1 or $s2           // Either $s1 or $s2 matches
  not $s1              // $s1 does not match
```

---

## 🛡️ Default Rules

Nebula Shield includes **12 default YARA rules**:

| Rule Name | Severity | Family | Description |
|-----------|----------|--------|-------------|
| EICAR_Test_File | test | Test | EICAR antivirus test file |
| WannaCry_Ransomware | critical | Ransomware | WannaCry ransomware detection |
| Emotet_Banking_Trojan | critical | Trojan | Emotet banking trojan |
| CobaltStrike_Beacon | critical | Framework | Cobalt Strike beacon |
| Mimikatz_Credential_Dumper | critical | Stealer | Mimikatz credential dumper |
| PowerShell_Empire | critical | Framework | PowerShell Empire framework |
| Meterpreter_Payload | critical | Backdoor | Metasploit Meterpreter |
| Suspicious_PowerShell_Script | high | Script | Suspicious PowerShell indicators |
| PHP_Web_Shell | critical | WebShell | PHP web shell detection |
| Ransomware_Generic | critical | Ransomware | Generic ransomware indicators |
| Generic_Keylogger | high | Spyware | Keylogger detection |
| Cryptocurrency_Miner | medium | Miner | Crypto mining malware |

---

## ✏️ Creating Custom Rules

### Example 1: Detecting a Custom Backdoor

```yara
rule Custom_Backdoor_2025 {
  meta:
    description = "Custom backdoor detection for 2025"
    author = "Security Team"
    severity = "critical"
    malware_family = "Backdoor"
    date = "2025-10-13"
    
  strings:
    $magic = { 4D 5A }  // MZ header
    $cmd1 = "cmd.exe /c" nocase
    $cmd2 = "powershell.exe -ep bypass" nocase
    $net1 = "socket.connect" nocase
    $net2 = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}/
    
  condition:
    $magic at 0 and (2 of ($cmd*) or 1 of ($net*))
}
```

### Example 2: Detecting Phishing Documents

```yara
rule Phishing_Document {
  meta:
    description = "Detects phishing documents with macros"
    author = "Threat Intel Team"
    severity = "high"
    malware_family = "Phishing"
    
  strings:
    $doc = { D0 CF 11 E0 }  // Office document header
    $macro1 = "AutoOpen" nocase
    $macro2 = "Document_Open" nocase
    $suspicious1 = "WScript.Shell" nocase
    $suspicious2 = "CreateObject" nocase
    $url = /https?:\/\/[a-zA-Z0-9.-]+\.[a-z]{2,}/
    
  condition:
    $doc at 0 and 
    (1 of ($macro*)) and 
    (1 of ($suspicious*)) and 
    $url
}
```

### Example 3: Detecting Obfuscated JavaScript

```yara
rule Obfuscated_JavaScript {
  meta:
    description = "Detects heavily obfuscated JavaScript"
    author = "Web Security Team"
    severity = "medium"
    malware_family = "Script"
    
  strings:
    $eval1 = "eval(" nocase
    $eval2 = "eval(unescape" nocase
    $eval3 = "eval(atob" nocase
    $obf1 = "String.fromCharCode"
    $obf2 = "\\x" // Hex encoded
    $obf3 = "\\u" // Unicode encoded
    
  condition:
    (1 of ($eval*)) and (2 of ($obf*))
}
```

---

## 🔧 Advanced Features

### 1. Pattern Wildcards

```yara
strings:
  // Single byte wildcard
  $hex1 = { 4D 5A ?? ?? 50 45 }
  
  // Range wildcards
  $hex2 = { 4D 5A [4-8] 50 45 }  // 4 to 8 any bytes
  $hex3 = { 4D 5A [0-16] 50 45 }  // 0 to 16 bytes
```

### 2. Multiple Conditions

```yara
condition:
  // Complex boolean logic
  ($s1 and $s2) or ($s3 and not $s4)
  
  // Count-based
  #s1 > 5  // $s1 appears more than 5 times
  
  // Position-based
  $magic at 0  // $magic at offset 0
```

### 3. Rule Sets

Group related rules for efficient scanning:

```javascript
// Import multiple rules at once
const ruleset = `
rule Rule1 { ... }
rule Rule2 { ... }
rule Rule3 { ... }
`;

const results = yaraEngine.importRules(ruleset);
console.log(`Imported ${results.success} rules, ${results.failed} failed`);
```

---

## 🔗 Integration

### With Enhanced Scanner

```javascript
import yaraEngine from './services/yaraEngine';
import enhancedScanner from './services/enhancedScanner';

// Add YARA scan to scanner workflow
const scanWithYara = async (filePath, content) => {
  // Run standard signature scan
  const signatureResults = await enhancedScanner.quickScan(filePath);
  
  // Run YARA rules
  const yaraMatches = yaraEngine.scanContent(content, filePath);
  
  // Combine results
  return {
    signatureThreats: signatureResults.threats,
    yaraThreats: yaraMatches,
    totalThreats: signatureResults.threats.length + yaraMatches.length
  };
};
```

### With Real-Time Monitoring

```javascript
// Monitor file changes and scan with YARA
const fs = require('fs');

fs.watch('/path/to/monitor', (eventType, filename) => {
  if (eventType === 'change') {
    const content = fs.readFileSync(filename);
    const matches = yaraEngine.scanContent(content, filename);
    
    if (matches.length > 0) {
      console.warn(`⚠️ Threat detected in ${filename}`);
      matches.forEach(m => console.log(`  - ${m.rule}: ${m.meta.description}`));
    }
  }
});
```

---

## 💡 Best Practices

### 1. **Performance Optimization**

✅ **Use specific patterns** instead of broad regex  
✅ **Limit wildcards** in hex patterns  
✅ **Avoid excessive string counts**  
✅ **Test rules on clean files** to minimize false positives  

### 2. **Rule Quality**

✅ **Add detailed metadata** for attribution  
✅ **Include severity levels** for prioritization  
✅ **Reference CVEs or reports** when applicable  
✅ **Test against known samples** before deployment  

### 3. **Organization**

✅ **Group rules by malware family**  
✅ **Use consistent naming conventions**  
✅ **Version control your rulesets**  
✅ **Document rule purposes**  

### 4. **False Positive Reduction**

✅ **Use multiple string conditions**  
✅ **Include unique identifiers**  
✅ **Avoid common legitimate strings**  
✅ **Test on enterprise software**  

---

## 📚 Examples

### Example 1: Detect Log4Shell Exploit

```yara
rule Log4Shell_Exploit_CVE_2021_44228 {
  meta:
    description = "Detects Log4Shell (Log4j) JNDI injection attempts"
    author = "Nebula Shield"
    severity = "critical"
    reference = "CVE-2021-44228"
    date = "2025-10-13"
    
  strings:
    $jndi1 = "${jndi:ldap://" nocase
    $jndi2 = "${jndi:rmi://" nocase
    $jndi3 = "${jndi:dns://" nocase
    $jndi4 = "${jndi:ldaps://" nocase
    $obf1 = "${${" nocase
    $obf2 = "${lower:" nocase
    $obf3 = "${upper:" nocase
    
  condition:
    any of ($jndi*) or (2 of ($obf*))
}
```

### Example 2: Detect Ransomware Note

```yara
rule Ransomware_Ransom_Note {
  meta:
    description = "Detects ransomware ransom notes"
    author = "Nebula Shield"
    severity = "critical"
    malware_family = "Ransomware"
    
  strings:
    $decrypt1 = "HOW TO DECRYPT" nocase
    $decrypt2 = "README" nocase
    $bitcoin1 = "bitcoin" nocase
    $bitcoin2 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/  // Bitcoin address
    $payment1 = "payment" nocase
    $payment2 = "pay" nocase
    $files1 = "your files" nocase
    $files2 = "encrypted" nocase
    
  condition:
    (1 of ($decrypt*)) and 
    (1 of ($bitcoin*)) and 
    (1 of ($payment*)) and 
    (1 of ($files*))
}
```

### Example 3: Detect Credential Harvesting

```yara
rule Credential_Harvester {
  meta:
    description = "Detects credential harvesting scripts"
    author = "Nebula Shield"
    severity = "high"
    malware_family = "Stealer"
    
  strings:
    $login1 = "username" nocase
    $login2 = "password" nocase
    $harvest1 = "document.forms" nocase
    $harvest2 = "getElementById" nocase
    $exfil1 = "XMLHttpRequest" nocase
    $exfil2 = "fetch(" nocase
    $exfil3 = "POST" nocase
    
  condition:
    (all of ($login*)) and 
    (1 of ($harvest*)) and 
    (1 of ($exfil*))
}
```

---

## 🔌 API Reference

### YaraEngine Class

#### Methods

**compileRule(ruleText)**
- Compiles a YARA rule from text
- Returns: `{ success: boolean, rule?: string, error?: string }`

```javascript
const result = yaraEngine.compileRule(ruleText);
if (result.success) {
  console.log(`Rule ${result.rule} compiled successfully`);
}
```

**scanContent(content, fileName)**
- Scans content against all compiled rules
- Returns: `Array<Match>` where Match has:
  - `rule`: Rule name
  - `meta`: Rule metadata
  - `matchedStrings`: Array of matched patterns
  - `fileName`: Scanned file name
  - `timestamp`: ISO timestamp

```javascript
const matches = yaraEngine.scanContent(fileContent, 'suspicious.exe');
matches.forEach(match => {
  console.log(`Detected: ${match.rule}`);
});
```

**importRules(rulesText)**
- Imports multiple rules from text
- Returns: `{ success: number, failed: number, errors: Array<string> }`

```javascript
const result = yaraEngine.importRules(multipleRules);
console.log(`Imported ${result.success} rules`);
```

**exportRules()**
- Exports all compiled rules as text
- Returns: `string`

```javascript
const allRules = yaraEngine.exportRules();
fs.writeFileSync('my-rules.yar', allRules);
```

**getStats()**
- Returns statistics about loaded rules
- Returns: `{ totalRules, totalMatches, rulesByFamily, recentMatches }`

```javascript
const stats = yaraEngine.getStats();
console.log(`Total rules: ${stats.totalRules}`);
console.log(`Total matches: ${stats.totalMatches}`);
```

**listRules()**
- Lists all loaded rule names
- Returns: `Array<string>`

```javascript
const rules = yaraEngine.listRules();
console.log('Loaded rules:', rules.join(', '));
```

**getRule(name)**
- Gets a specific rule by name
- Returns: `Rule object or undefined`

```javascript
const rule = yaraEngine.getRule('WannaCry_Ransomware');
console.log(rule.meta.description);
```

**deleteRule(name)**
- Deletes a rule by name
- Returns: `boolean`

```javascript
yaraEngine.deleteRule('old_rule');
```

**clearHistory()**
- Clears match history
- Returns: `void`

```javascript
yaraEngine.clearHistory();
```

---

## 📊 Statistics & Monitoring

### Get Rule Statistics

```javascript
const stats = yaraEngine.getStats();

console.log(`Total Rules: ${stats.totalRules}`);
console.log(`Total Matches: ${stats.totalMatches}`);
console.log('\nRules by Family:');
Object.entries(stats.rulesByFamily).forEach(([family, count]) => {
  console.log(`  ${family}: ${count}`);
});
```

### Monitor Recent Matches

```javascript
const stats = yaraEngine.getStats();
console.log('\nRecent Detections:');
stats.recentMatches.forEach(match => {
  console.log(`  [${match.timestamp}] ${match.rule} in ${match.fileName}`);
});
```

---

## 🎓 Learning Resources

### Official YARA Resources
- **YARA Homepage:** https://virustotal.github.io/yara/
- **YARA Documentation:** https://yara.readthedocs.io/
- **YARA Rules Repository:** https://github.com/Yara-Rules/rules

### Community Resources
- **Awesome YARA:** https://github.com/InQuest/awesome-yara
- **YARA Exchange:** https://github.com/Neo23x0/signature-base
- **VirusTotal YARA:** https://support.virustotal.com/hc/en-us/articles/360001385897

---

## 🔒 Security Considerations

⚠️ **Important Security Notes:**

1. **Rule Sources** - Only import rules from trusted sources
2. **Regex DoS** - Avoid complex regex that could cause ReDoS
3. **False Positives** - Test rules thoroughly before deployment
4. **Performance** - Monitor rule execution time
5. **Updates** - Keep rules updated with latest threat intelligence

---

## 🐛 Troubleshooting

### Rule Not Matching

1. **Check Pattern Syntax** - Ensure patterns are correctly formatted
2. **Verify Modifiers** - Use `nocase` for case-insensitive matching
3. **Test Condition** - Ensure condition logic is correct
4. **Check File Encoding** - Use `wide` modifier for UTF-16

### Performance Issues

1. **Optimize Patterns** - Use specific strings instead of regex
2. **Reduce Rule Count** - Only load necessary rules
3. **Limit Wildcards** - Minimize [n-m] ranges in hex patterns
4. **Profile Rules** - Identify slow-running rules

---

## 📝 License

YARA Rule Engine for Nebula Shield  
Copyright (c) 2025 Nebula Shield Team  
Licensed under MIT License

---

## 🤝 Contributing

Submit your custom YARA rules:

1. **Fork the repository**
2. **Add your rules** to `custom-rules/`
3. **Test against samples**
4. **Submit pull request**

---

## 📞 Support

**Documentation:** https://docs.nebulashield.com/yara  
**Issues:** https://github.com/nebulashield/issues  
**Email:** yara-support@nebulashield.com

---

**Last Updated:** October 13, 2025  
**Version:** 1.0.0  
**Status:** Production Ready ✅

---

*🔍 Hunt threats with precision. YARA + Nebula Shield.*
