# Data Protection - Test Examples

## Sample PII Data for Testing

Use these examples to test the Data Protection scanner:

### Example 1: Financial Data
```
Customer Payment Information:
- Credit Card: 4532-1234-5678-9010
- CVV: 123
- Exp Date: 12/25
- Bank Account: 987654321
- Routing Number: 021000021
```

**Expected Detection:**
- 1 Credit Card Number (CRITICAL)
- 1 Bank Account Number (CRITICAL)
- Date of expiration (MEDIUM)

### Example 2: Identity Information
```
Employee Record:
Name: John Smith
SSN: 123-45-6789
Driver's License: D1234567
Passport: AB1234567
DOB: 01/15/1985
```

**Expected Detection:**
- 1 Social Security Number (CRITICAL)
- 1 Driver's License (HIGH)
- 1 Passport Number (CRITICAL)
- 1 Date of Birth (HIGH)

### Example 3: Contact Information
```
Contact Details:
Email: john.doe@example.com
Phone: (555) 123-4567
Mobile: +44 7123 456789
Address: 123 Main Street, Apt 4B
IP Address: 192.168.1.100
```

**Expected Detection:**
- 1 Email Address (HIGH)
- 2 Phone Numbers (MEDIUM)
- 1 Physical Address (MEDIUM)
- 1 IP Address (MEDIUM)

### Example 4: Medical Records (HIPAA)
```
Patient Information:
MRN: MRN-123456
Patient ID: 987654
Diagnosis: Hypertension
Prescription: Lisinopril 10mg
Blood Type: A+
Insurance ID: INS123456789
```

**Expected Detection:**
- 1 Medical Record Number (CRITICAL)
- Medical terminology keywords (HIGH)
- Insurance information (HIGH)

### Example 5: API Keys & Credentials
```
API Configuration:
API_KEY: sk_live_51HxYz1234567890abcdef
SECRET_KEY: whsec_abcdef123456789
PASSWORD: MyP@ssw0rd123!
Bearer Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

**Expected Detection:**
- 2 API Keys (CRITICAL)
- 1 Password (CRITICAL)
- 1 Bearer Token (CRITICAL)

### Example 6: Mixed PII (High Risk)
```
Wire Transfer Instructions:
Beneficiary: Jane Williams
SSN: 987-65-4321
Bank: Chase Bank
Account: 1234567890
Routing: 021000021
Amount: $50,000
Card for fees: 5105-1051-0510-5100
Email: jane.w@example.com
Phone: 555-987-6543
```

**Expected Detection:**
- 1 SSN (CRITICAL)
- 1 Bank Account (CRITICAL)
- 1 Credit Card (CRITICAL)
- 1 Email (HIGH)
- 1 Phone (MEDIUM)
- Financial keywords (HIGH)

**Expected Risk Score: 90+ (CRITICAL)**

### Example 7: Clean Text (Should be Safe)
```
Meeting Notes:
- Discussed Q4 strategy
- Team lunch on Friday
- New project kickoff next week
- Review quarterly goals
```

**Expected Detection:**
- 0 PII items
- Risk Score: 0 (SAFE)

### Example 8: GDPR Compliance Test
```
EU Customer Data:
Name: Hans Mueller
Email: hans.mueller@example.de
Phone: +49 30 12345678
Address: Friedrichstrasse 123, Berlin
National ID: DE123456789
IP: 2001:0db8:85a3::8a2e:0370:7334
```

**Expected Detection:**
- Multiple PII items
- GDPR compliance triggered
- Location data flagged

---

## Testing Workflow

### 1. Basic Scan
1. Copy "Example 1" above
2. Paste into scanner
3. Click "Scan for PII"
4. Review detected items

### 2. Redaction Test
1. Use "Example 6" (mixed PII)
2. Click "Redact PII"
3. Compare original vs redacted
4. Copy redacted text

### 3. Data Leak Prevention
1. Paste "Example 5" (credentials) into scanner
2. Go to "Data Leak Prevention" tab
3. Click "Test Clipboard Leak"
4. Should show CRITICAL alert and BLOCKED status

### 4. Compliance Report
1. Scan "Example 8" (GDPR)
2. Go to "Compliance Reports" tab
3. Select "GDPR"
4. Generate report
5. Review compliance status

### 5. File Upload Test
Create a text file with Example 6 content and test file upload feature.

---

## Expected Results Summary

| Example | PII Count | Risk Score | Compliance |
|---------|-----------|------------|------------|
| Example 1 | 2-3 | 60-70 | PCI-DSS |
| Example 2 | 4 | 80-90 | GDPR, CCPA |
| Example 3 | 5 | 50-60 | GDPR |
| Example 4 | 2-3 | 70-80 | HIPAA |
| Example 5 | 4 | 90-100 | ISO 27001 |
| Example 6 | 5+ | 90-100 | Multiple |
| Example 7 | 0 | 0 | N/A |
| Example 8 | 5+ | 70-80 | GDPR |

---

## Advanced Testing

### False Positive Check
```
This is a test with numbers that look like PII but aren't:
- Order ID: 1234567890 (10 digits but not SSN)
- Reference: 4000-0000-0000-0000 (test card number)
- Code: 123-45-6789 (SSN format but in code context)
```

The scanner should still detect these due to pattern matching, but validation algorithms will help filter some false positives.

### Edge Cases
```
Edge case testing:
- Phone with extension: (555) 123-4567 x890
- International SSN: 12-3456789 (invalid format)
- Partial credit card: ****-****-****-1234
- Masked email: j***@example.com
```

### Performance Test
Paste 10,000+ words of text with scattered PII to test scanning speed.

---

## Pro Tips

1. **Use Example 6** for comprehensive feature testing
2. **Start with Example 7** to verify no false alarms
3. **Test compliance** with region-specific examples
4. **Try file upload** with multiple examples in one file
5. **Monitor statistics** after each test

---

Happy Testing! 🛡️
