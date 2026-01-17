# SQL Injection Assessment – Sample Report

**Project:** SQLi Scanner (Form-Based Detection)  
**Target:** http://testphp.vulnweb.com  
**Assessment Type:** Automated Detection (Error-Based Heuristics)  
**Date:** 2026-01-16  
**Analyst:** Smriti Singh

---

## Executive Summary

An automated SQL Injection (SQLi) assessment was performed against a deliberately vulnerable test application to identify potential input validation weaknesses.

The scanner detected **one form input potentially vulnerable to SQL injection**, based on database error patterns observed in server responses.

This assessment was conducted for **educational and authorized testing purposes only**.

---

## Scope

- **In Scope**
  - Publicly accessible web application
  - HTML form inputs on the landing page

- **Out of Scope**
  - Authenticated areas
  - Manual exploitation
  - Data extraction or modification

---

## Methodology

The assessment followed a detection-only workflow:

1. Discover HTML forms on the target page
2. Inject common SQLi payloads into form fields
3. Analyze HTTP responses for known SQL error signatures
4. Flag inputs showing potential SQLi indicators

---

## Findings Summary

| ID | Vulnerability | Severity | Status |
|----|---------------|----------|--------|
| SQLI-01 | SQL Injection (Error-Based) | High | Open |

---

## Finding Details

### SQLI-01 – SQL Injection (Error-Based)

- **Affected URL:** `http://testphp.vulnweb.com`
- **Affected Parameter:** `search`
- **Form Method:** POST
- **Payload Used:** `' OR '1'='1' --`
- **Evidence:**  
  Server response contained database error messages indicating improper input handling.

- **Impact:**  
  An attacker may be able to manipulate backend SQL queries, potentially leading to:
  - Unauthorized data access
  - Authentication bypass
  - Data integrity compromise

- **Severity:** High  
  (Based on OWASP risk rating: high impact, medium likelihood)

---

## Recommendations

- Use parameterized queries / prepared statements
- Apply strict server-side input validation
- Disable detailed database error messages in production
- Employ a Web Application Firewall (WAF)

---

## Limitations

- Error-based detection can produce false positives
- Dynamic content may affect response comparison
- Findings require manual verification using tools such as Burp Suite

---

## Conclusion

The assessment identified a **potential SQL injection vulnerability** that should be validated and remediated.  
This project demonstrates how automated detection can assist security analysts during early-stage assessments.
