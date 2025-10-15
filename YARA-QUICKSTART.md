# 🔍 YARA Rule Support - Quick Start
## Nebula Shield Anti-Virus

---

## ✨ Features

✅ **12 Pre-loaded Rules** - Ready-to-use YARA rules for common threats  
✅ **Custom Rule Creation** - Build your own detection patterns  
✅ **Import/Export** - Share rules with the community  
✅ **Real-time Scanning** - Integrate with file scanning  
✅ **Visual Rule Manager** - User-friendly UI for managing rules  
✅ **Pattern Types** - Text, Hex, and Regex patterns  
✅ **Metadata Support** - Track rule authors, severity, and families  
✅ **Advanced Conditions** - Boolean logic for complex detection  

---

## 🚀 Getting Started

### 1. Access YARA Manager

Navigate to the YARA Rules Manager in your Nebula Shield dashboard.

### 2. View Default Rules

The system comes with 12 pre-loaded rules:
- EICAR Test File
- WannaCry Ransomware
- Emotet Banking Trojan
- Cobalt Strike Beacon
- Mimikatz Credential Dumper
- PowerShell Empire
- Meterpreter Payload
- Suspicious PowerShell Script
- PHP Web Shell
- Generic Ransomware
- Generic Keylogger
- Cryptocurrency Miner

### 3. Create Your First Rule

Click "Add Rule" and use this template:

```yara
rule My_First_Rule {
  meta:
    description = "My custom threat detection"
    author = "Your Name"
    severity = "high"
    
  strings:
    $s1 = "malicious_pattern" nocase
    $s2 = { 4D 5A 90 00 }
    
  condition:
    any of them
}
```

### 4. Test Your Rule

The rule is automatically compiled and ready to use in scans.

---

## 📖 Rule Syntax

### Basic Structure

```yara
rule RuleName {
  meta:
    description = "What this rule detects"
    author = "Your name"
    severity = "critical|high|medium|low"
    
  strings:
    $variable = "pattern"
    
  condition:
    $variable
}
```

### Pattern Types

**Text Patterns:**
```yara
$text = "malware" nocase
```

**Hex Patterns:**
```yara
$hex = { 4D 5A 90 00 }
```

**Regex Patterns:**
```yara
$regex = /malware|trojan/i
```

### Modifiers

- `nocase` - Case-insensitive
- `wide` - UTF-16 encoding
- `ascii` - ASCII encoding (default)
- `fullword` - Complete word matching

### Conditions

```yara
any of them          # At least one match
all of them          # All must match
2 of them            # At least 2 matches
$s1 and $s2          # Both must match
$s1 or $s2           # Either matches
```

---

## 🎯 Common Use Cases

### Detect Ransomware

```yara
rule Ransomware_Indicator {
  meta:
    description = "Generic ransomware detection"
    severity = "critical"
    
  strings:
    $ransom1 = "DECRYPT" nocase
    $ransom2 = "bitcoin" nocase
    $ransom3 = "encrypted" nocase
    
  condition:
    2 of them
}
```

### Detect Web Shells

```yara
rule WebShell_PHP {
  meta:
    description = "PHP web shell"
    severity = "critical"
    
  strings:
    $php1 = "<?php" nocase
    $cmd1 = "eval($_POST" nocase
    $cmd2 = "shell_exec" nocase
    
  condition:
    $php1 and (1 of ($cmd*))
}
```

### Detect Obfuscated Scripts

```yara
rule Obfuscated_JavaScript {
  meta:
    description = "Obfuscated JS malware"
    severity = "medium"
    
  strings:
    $eval = "eval(" nocase
    $obf1 = "String.fromCharCode"
    $obf2 = "\\x"
    
  condition:
    $eval and (1 of ($obf*))
}
```

---

## 🔧 Integration

### Scan Files with YARA

```javascript
import enhancedScanner from './services/enhancedScanner';

// Scan content with YARA rules
const content = fs.readFileSync('suspicious-file.exe');
const matches = enhancedScanner.scanWithYara(content, 'suspicious-file.exe');

if (matches.length > 0) {
  console.log('Threats detected!');
  matches.forEach(match => {
    console.log(`Rule: ${match.rule}`);
    console.log(`Description: ${match.meta.description}`);
  });
}
```

### Add Custom Rule Programmatically

```javascript
const customRule = `
rule Custom_Threat {
  meta:
    description = "Custom malware"
    author = "Security Team"
    
  strings:
    $s1 = "malicious"
    
  condition:
    $s1
}
`;

const result = enhancedScanner.compileYaraRule(customRule);
console.log(result.success ? 'Rule added!' : 'Failed to compile');
```

### Import Rules from File

```javascript
const fs = require('fs');
const rulesText = fs.readFileSync('my-rules.yar', 'utf8');
const result = enhancedScanner.importYaraRules(rulesText);
console.log(`Imported ${result.success} rules`);
```

---

## 📊 Statistics

### View Rule Stats

```javascript
const stats = enhancedScanner.getYaraStats();

console.log(`Total Rules: ${stats.totalRules}`);
console.log(`Total Matches: ${stats.totalMatches}`);
console.log('Rules by Family:', stats.rulesByFamily);
```

### List All Rules

```javascript
const rules = enhancedScanner.listYaraRules();
console.log('Loaded rules:', rules);
```

### Get Rule Details

```javascript
const rule = enhancedScanner.getYaraRule('WannaCry_Ransomware');
console.log(rule.meta.description);
console.log(`Patterns: ${Object.keys(rule.strings).length}`);
```

---

## 💡 Best Practices

### 1. Performance

✅ Use specific patterns instead of broad regex  
✅ Limit wildcard usage in hex patterns  
✅ Test rules on clean files first  
✅ Avoid overly complex conditions  

### 2. Accuracy

✅ Use multiple string patterns  
✅ Include unique identifiers  
✅ Test against known samples  
✅ Add detailed metadata  

### 3. Organization

✅ Group rules by malware family  
✅ Use consistent naming (Family_Variant)  
✅ Document rule purposes  
✅ Version control your rules  

### 4. False Positives

✅ Avoid common legitimate strings  
✅ Use multiple conditions (2+ matches)  
✅ Test on enterprise software  
✅ Include severity levels  

---

## 🐛 Troubleshooting

### Rule Not Compiling

**Problem:** Syntax error in rule  
**Solution:** Check brackets, quotes, and semicolons

### Rule Not Matching

**Problem:** Pattern not found  
**Solution:** Use `nocase` modifier or check encoding

### Performance Issues

**Problem:** Slow scanning  
**Solution:** Optimize patterns, reduce regex complexity

---

## 📚 Resources

### Official YARA
- Homepage: https://virustotal.github.io/yara/
- Documentation: https://yara.readthedocs.io/

### Rule Collections
- Yara-Rules: https://github.com/Yara-Rules/rules
- Signature Base: https://github.com/Neo23x0/signature-base

### Learning
- Awesome YARA: https://github.com/InQuest/awesome-yara
- Tutorial: https://yara.readthedocs.io/en/stable/gettingstarted.html

---

## 🔒 Security Notes

⚠️ **Important:**
- Only import rules from trusted sources
- Test rules before production use
- Monitor rule performance
- Keep rules updated
- Avoid regex ReDoS vulnerabilities

---

## 📞 Support

**Full Documentation:** `YARA-SUPPORT-GUIDE.md`  
**Issues:** https://github.com/nebulashield/issues  
**Email:** support@nebulashield.com

---

## 🎓 Example Rules

See `/examples/yara-rules/` for:
- Ransomware detection
- APT indicators
- Web shell patterns
- Exploit signatures
- Phishing indicators

---

**Version:** 1.0.0  
**Status:** Production Ready ✅  
**Last Updated:** October 13, 2025

---

*🔍 Detect threats with precision using YARA + Nebula Shield!*
