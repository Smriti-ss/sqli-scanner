![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

# SQL Injection Scanner

A lightweight Python tool that detects potential SQL Injection (SQLi) vulnerabilities by automatically testing HTML form inputs with common SQLi payloads and identifying database error patterns in responses.

⚠️ **IMPORTANT:** Authorized use only — scan applications you own or have explicit permission to test.

## Purpose

SQL injection remains one of the most critical web vulnerabilities (OWASP Top 10). This scanner helps security professionals identify SQLi vulnerabilities during penetration testing and security audits.

## Why this Project?

SQL Injection remains one of the most prevalent and high-impact web vulnerabilities.
This project was built to demonstrate:
-Application Security (AppSec) fundamentals
-Automated vulnerability detection workflows
-Safe, non-exploitative testing techniques
-Professional security reporting (JSON + Markdown)

The focus is on detection and analysis, not exploitation.

## Features

- **Automatic form detection** - Finds and extracts all forms from target URLs
- **14 SQLi payload testing** - Tests common injection patterns
- **Error-based detection** - Identifies vulnerabilities through SQL error patterns (MySQL, MSSQL, PostgreSQL signatures)
- **JSON report export** - For dashboards or further analysis
- **Colored output** - Clear, readable results with color-coded findings
- **Sample assessment report** - Included (docs/sample-report.md)
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
### JSON Report Output
Generate a structured JSON report for integration with security workflows or dashboards:
```bash
python ./sqli_scanner.py http://testphp.vulnweb.com --json report.json --pretty
```

--json report.json → writes findings to file

--pretty → human-readable formatted JSON

Generated reports are ignored via .gitignore to keep the repo clean.

### Custom timeout:
```bash
python sqli_scanner.py http://testphp.vulnweb.com --timeout 15
```

## How It Works

1. Fetch target page
2. Discover HTML forms
3. Inject SQLi payloads into form fields
4. Submit GET/POST requests
5. Analyze responses for SQL error patterns
6. Record findings and export results

## Sample Findings

Each finding includes:
-Affected URL & form action
-HTTP method
-Vulnerable input fields
-Payload used
-Detected error pattern
-Severity classification
-Mitigation recommendations

See:
📁 docs/sample-report.md

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
- **JSON Reporting**: Security workflows for reporting result
- **Python development**: Building CLI tools with argparse, error handling, and colored output

## Related Blog

- Read my Medium article: [SQL Injection Didn't Die — It Got Smarter with AI](#) *((https://medium.com/meetcyber/sql-injection-didnt-die-it-got-smarter-with-ai-fe21ac195be9))*

## License

MIT License — see LICENSE

## Disclaimer

This tool is for educational and authorized security testing purposes only. The author is not responsible for misuse or damage caused by this tool. Always obtain proper authorization before testing any system.

---

⭐ **Star this repo if you found it useful!**
