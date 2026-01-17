# SQL Injection Scanner

An automated Python tool that detects SQL injection vulnerabilities in web applications by testing forms with common SQLi payloads and analyzing error patterns.

## Purpose

SQL injection remains one of the most critical web vulnerabilities (OWASP Top 10). This scanner helps security professionals identify SQLi vulnerabilities during penetration testing and security audits.

**IMPORTANT:** Only use this tool on websites you own or have explicit permission to test. Unauthorized security testing is illegal.

## Features

- **Automatic form detection** - Finds and extracts all forms from target URLs
- **14 SQLi payload testing** - Tests common injection patterns
- **Error-based detection** - Identifies vulnerabilities through SQL error patterns
- **Colored output** - Clear, readable results with color-coded findings
- **Detailed reporting** - Shows vulnerable forms, payloads, and affected fields
- **Security recommendations** - Provides remediation guidance
- **Verbose mode** - Optional detailed logging for testing

## Installation

pip install -r requirements.txt

**Setup:**
```bash
git clone https://github.com/Smriti-ss/sqli-scanner.git
cd sqli-scanner
pip install requests beautifulsoup4 colorama
```

## Usage

### Basic scan:
```bash
python sqli_scanner.py http://testphp.vulnweb.com
```

### Verbose mode (detailed output):
```bash
python sqli_scanner.py http://testphp.vulnweb.com --verbose
```

### Custom timeout:
```bash
python sqli_scanner.py http://testphp.vulnweb.com --timeout 15
```

## Example Output
```
======================================================================
SQL INJECTION SCANNER
======================================================================

Target: http://testphp.vulnweb.com
Started: 2026-01-17 00:51:18

⚠ WARNING: Only scan websites you own or have permission to test!
======================================================================

→ Searching for forms...
✓ Found 1 form(s) to test

→ Testing form #1
  Action: http://testphp.vulnweb.com/search.php?test=query
  Method: POST
  ✗ VULNERABLE - Payload: ' OR '1'='1' --...
    Error pattern detected: you have an error in your sql syntax

======================================================================
SCAN RESULTS
======================================================================

Forms tested: 1
Payloads per form: 14

⚠ VULNERABILITIES FOUND: 1

Vulnerability #1:
  Form: http://testphp.vulnweb.com/search.php?test=query
  Method: POST
  Payload: ' OR '1'='1' --
  Error Pattern: you have an error in your sql syntax
  Vulnerable Fields: searchFor

======================================================================
RECOMMENDATION:
  - Use parameterized queries/prepared statements
  - Implement input validation and sanitization
  - Use an ORM framework with built-in protections
  - Apply principle of least privilege for database access
======================================================================
```

## How It Works

1. **Form Discovery**: Scrapes the target URL and extracts all HTML forms
2. **Payload Injection**: Tests each form input with 14 common SQLi payloads
3. **Error Detection**: Analyzes responses for SQL error patterns
4. **Result Reporting**: Displays vulnerable forms with detailed information

## Testing Payloads

The scanner tests various SQLi techniques:
- Classic SQLi (`' OR '1'='1`)
- Comment-based injection (`admin' --`)
- UNION-based injection (`' UNION SELECT NULL--`)
- Logical operators (`' AND 1=1--`)
- Alternative quote styles (`" OR "1"="1`)

## Legal & Ethical Use

**ONLY test on:**
- Your own applications
- Deliberately vulnerable test sites (testphp.vulnweb.com, DVWA, etc.)
- Bug bounty programs with explicit permission
- Client applications with written authorization

**NEVER test on:**
- Public websites without permission
- Production systems without authorization
- Any system you don't own or haven't been explicitly authorized to test

Unauthorized security testing is illegal and can result in criminal charges.

## Safe Testing Environments

Practice on these legal, deliberately vulnerable sites:
- [testphp.vulnweb.com](http://testphp.vulnweb.com)
- [DVWA (Damn Vulnerable Web Application)](http://www.dvwa.co.uk/)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [PortSwigger Web Security Academy Labs](https://portswigger.net/web-security)

## What I Learned

- **Web vulnerability assessment**: Understanding SQLi attack vectors and detection methods
- **Web scraping**: Using BeautifulSoup to parse HTML and extract forms
- **HTTP protocols**: Working with GET/POST requests and form submissions
- **Error pattern recognition**: Identifying SQL errors across different database systems
- **Security best practices**: Ethical testing, responsible disclosure, and remediation
- **Python development**: Building CLI tools with argparse, error handling, and colored output

## Related Blog

- Read my Medium article: [SQL Injection Didn't Die — It Got Smarter with AI](#) *((https://medium.com/meetcyber/sql-injection-didnt-die-it-got-smarter-with-ai-fe21ac195be9))*

## Disclaimer

This tool is for educational and authorized security testing purposes only. The author is not responsible for misuse or damage caused by this tool. Always obtain proper authorization before testing any system.

---

⭐ **Star this repo if you found it useful!**
