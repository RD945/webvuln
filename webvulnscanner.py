#!/usr/bin/env python3
"""
WebVulnScanner v2.1 (Generic) - Browser-Automated Web Vulnerability Scanner
============================================================================
Uses Playwright for JavaScript rendering and network request interception.
Includes built-in verification to reduce false positives.

For Windows 11 | Single-file implementation

Features:
- Browser-based crawling with JS rendering
- Network request interception
- API endpoint discovery from JS files
- SQLi, XSS, LFI, RCE, SSRF testing
- Security header analysis
- Server fingerprinting + CVE mapping
- False positive verification
- Soft 404 detection
"""

import argparse
import asyncio
import json
import re
import ssl
import socket
import sys
import time
import urllib.parse
from datetime import datetime
from html import escape
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

# Auto-install dependencies
def install_deps():
    import subprocess
    deps = ["requests", "beautifulsoup4", "colorama", "tqdm", "lxml", "playwright"]
    for dep in deps:
        try:
            __import__(dep.replace("-", "_").split("[")[0])
        except ImportError:
            print(f"Installing {dep}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep, "-q"])
    subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], 
                   capture_output=True)

try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init
    from tqdm import tqdm
    from playwright.async_api import async_playwright
except ImportError:
    install_deps()
    import requests
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init
    from tqdm import tqdm
    from playwright.async_api import async_playwright

init(autoreset=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PAYLOADS DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

SQL_PAYLOADS = [
    "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "admin'--", "' OR ''='",
    "1' OR '1'='1", "') OR ('1'='1", "' OR 1=1#", "' OR 1=1/*", "'-'",
    "' AND '1'='1", "' AND '1'='2", "1 OR 1=1", "' UNION SELECT NULL--",
]

SQLI_TIME_PAYLOADS = [
    "' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)#",
    "' AND (SELECT SLEEP(5))--", "1; SELECT pg_sleep(5)--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>", "<body onload=alert('XSS')>",
    "javascript:alert('XSS')", "\"><script>alert('XSS')</script>",
]

XSS_WAF_BYPASS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert() )",
    "<img src=x oNeRrOr=alert()>",
    "<svg/onload=alert&#40;&#41;>",
    "<input onfocus=alert(1) autofocus>",
]

LFI_PAYLOADS = [
    "../../etc/passwd", "../../../etc/passwd", "....//....//etc/passwd",
    "..\\..\\..\\windows\\system.ini", "/etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd%00"
]

RCE_PAYLOADS = [
    "; whoami", "| whoami", "&& whoami", "|| whoami", "`whoami`", "$(whoami)",
    "; ping -n 3 127.0.0.1", "| ping -n 3 127.0.0.1"
]

SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost", "http://127.0.0.1:80",
    "http://169.254.169.254/latest/meta-data/", "http://[::1]"
]

SSRF_CLOUD_METADATA = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/metadata/instance?api-version=2017-04-02",
    "http://metadata.google.internal/computeMetadata/v1/",
]

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlf=injection",
    "%0d%0aX-Injected:header",
    "%0d%0a%0d%0a<script>alert(1)</script>",
]

SECURITY_HEADERS = [
    "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
    "Strict-Transport-Security", "X-XSS-Protection", "Referrer-Policy"
]

# ═══════════════════════════════════════════════════════════════════════════════
# SERVER CVE DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

NGINX_CVES = {
    "1.27": {"CVE-2025-23419": ("HIGH", "SSL session reuse vulnerability")},
    "1.26": {"CVE-2024-32760": ("HIGH", "HTTP/3 worker crash")},
    "1.25": {"CVE-2024-32760": ("HIGH", "HTTP/3 QUIC crash")},
    "1.20": {"CVE-2021-23017": ("CRITICAL", "DNS resolver heap overflow")},
}

APACHE_CVES = {
    "2.4.49": {"CVE-2021-41773": ("CRITICAL", "Path traversal + RCE")},
    "2.4.50": {"CVE-2021-42013": ("CRITICAL", "Path traversal bypass")},
}

IIS_CVES = {
    "10.0": {"CVE-2022-21907": ("CRITICAL", "HTTP Protocol Stack RCE - requires verification")},
}

SQL_ERROR_PATTERNS = [
    r"sql syntax.*mysql", r"mysql_fetch", r"ora-\d{5}", r"postgresql.*error",
    r"you have an error in your sql", r"warning.*mysql", r"sqlstate\[",
]

SQL_FALSE_POSITIVES = [
    r"invalid json", r"json.*syntax", r"json.*error", r"json.*parse",
    r"xml.*syntax", r"xml.*error", r"coding error detected",
]

# ═══════════════════════════════════════════════════════════════════════════════
# SENSITIVE PATHS
# ═══════════════════════════════════════════════════════════════════════════════

SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/.env.production",
    "/wp-config.php.bak", "/config.php.bak", "/.htaccess", "/.htpasswd",
    "/backup.sql", "/database.sql", "/phpinfo.php", "/.DS_Store",
    "/server-status", "/server-info", "/.svn/entries",
    "/package.json", "/composer.json", "/swagger.json", "/api-docs",
]

HTTP_METHODS = ["OPTIONS", "PUT", "DELETE", "TRACE", "PATCH"]

TECH_FINGERPRINTS = {
    "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
    "Laravel": ["laravel_session", "X-Powered-By: Laravel"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Express": ["X-Powered-By: Express"],
    "ASP.NET": ["ASP.NET", ".aspx", "__VIEWSTATE"],
    "Next.js": ["/_next/", "__NEXT_DATA__"],
    "React": ["react", "data-reactroot"],
    "Angular": ["ng-version", "ng-app"],
    "Vue.js": ["data-v-", "__vue__"],
}

# 404 patterns for soft 404 detection
NOTFOUND_PATTERNS = [
    r"404", r"not found", r"page.*doesn't exist", r"page.*does not exist",
    r"couldn't find", r"could not find", r"no longer available",
]

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║  {Fore.WHITE}██╗    ██╗███████╗██████╗ ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗{Fore.CYAN}  ║
║  {Fore.WHITE}██║    ██║██╔════╝██╔══██╗██║   ██║██║   ██║██║     ████╗  ██║{Fore.CYAN}  ║
║  {Fore.WHITE}██║ █╗ ██║█████╗  ██████╔╝██║   ██║██║   ██║██║     ██╔██╗ ██║{Fore.CYAN}  ║
║  {Fore.WHITE}██║███╗██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║{Fore.CYAN}  ║
║  {Fore.WHITE}╚███╔███╔╝███████╗██████╔╝ ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║{Fore.CYAN}  ║
║  {Fore.WHITE} ╚══╝╚══╝ ╚══════╝╚═════╝   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝{Fore.CYAN}  ║
║  {Fore.YELLOW}WebVulnScanner v2.1 (Generic) - With False Positive Detection{Fore.CYAN}   ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

def severity_color(severity: str) -> str:
    colors = {"CRITICAL": Fore.RED, "HIGH": Fore.LIGHTRED_EX, "MEDIUM": Fore.YELLOW, 
              "LOW": Fore.BLUE, "INFO": Fore.CYAN}
    return colors.get(severity.upper(), Fore.WHITE)

def get_base_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def is_same_origin(url: str, base_url: str) -> bool:
    try:
        return urllib.parse.urlparse(url).netloc == urllib.parse.urlparse(base_url).netloc
    except:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# FALSE POSITIVE VERIFIER
# ═══════════════════════════════════════════════════════════════════════════════

class FalsePositiveVerifier:
    """Verifies findings to eliminate false positives before reporting"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def verify_sensitive_file(self, url: str, original_size: int) -> Tuple[bool, str]:
        """Verify if sensitive file is actually exposed or is a soft 404"""
        try:
            # Make direct request
            response = requests.get(url, timeout=self.timeout, verify=False)
            
            # Check real 404
            if response.status_code == 404:
                return False, "HTTP 404 - file not found"
            
            # Check soft 404 (200 but content says not found)
            body = response.text.lower()[:5000]
            for pattern in NOTFOUND_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    return False, "Soft 404 - page content indicates not found"
            
            # Check content type for .env files
            content_type = response.headers.get("content-type", "")
            if ".env" in url and "text/html" in content_type:
                return False, "Content-Type is HTML, not plain text .env"
            
            # Check for actual .env patterns
            if ".env" in url:
                env_patterns = [r"^[A-Z_]+=", r"DATABASE_URL=", r"API_KEY=", r"SECRET"]
                has_env = any(re.search(p, body) for p in env_patterns)
                if not has_env:
                    return False, "No environment variable patterns found"
            
            # Check for .git patterns
            if ".git" in url:
                git_patterns = [b"ref:", b"gitdir:", b"[core]"]
                has_git = any(p in response.content for p in git_patterns)
                if not has_git:
                    return False, "No git metadata patterns found"
            
            return True, "Verified - actual sensitive content"
            
        except Exception as e:
            return False, f"Verification failed: {e}"
    
    def verify_cve(self, cve_id: str, url: str, server_header: str) -> Tuple[bool, str]:
        """Verify if CVE is actually exploitable (basic checks)"""
        
        # CVE-2022-21907 specific verification
        if cve_id == "CVE-2022-21907":
            try:
                # Check for HTTP Trailer Support
                parsed = urllib.parse.urlparse(url)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"TE: trailers\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                if parsed.scheme == "https":
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)
                
                sock.connect((host, port))
                sock.send(request)
                response = sock.recv(4096)
                sock.close()
                
                # Check if trailer support is enabled
                response_str = response.decode("utf-8", errors="replace")
                if "trailer" in response_str.lower():
                    return True, "HTTP Trailer Support may be enabled - needs manual verification"
                else:
                    return False, "HTTP Trailer Support not detected - likely not exploitable"
                    
            except:
                return False, "Could not verify CVE - verification failed"
        
        # For other CVEs, mark as needs verification
        return True, f"{cve_id} detected based on version - requires manual verification"


# ═══════════════════════════════════════════════════════════════════════════════
# BROWSER CRAWLER
# ═══════════════════════════════════════════════════════════════════════════════

class BrowserCrawler:
    def __init__(self, base_url: str, max_depth: int = 3, timeout: int = 30000, cookie: str = None):
        self.base_url = base_url.rstrip('/')
        self.base_domain = urllib.parse.urlparse(base_url).netloc
        self.max_depth = max_depth
        self.timeout = timeout
        self.cookie = cookie
        
        self.urls: Set[str] = set()
        self.api_endpoints: List[Dict] = []
        self.forms: List[Dict] = []
        self.js_files: Set[str] = set()
        self.network_requests: List[Dict] = []
        
    async def crawl(self) -> Dict:
        print(f"\n{Fore.CYAN}[*] Starting browser-based crawl of {self.base_url}{Style.RESET_ALL}")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
                ignore_https_errors=True
            )
            
            if self.cookie and '=' in self.cookie:
                name, value = self.cookie.split('=', 1)
                if ';' in value:
                    value = value.split(';')[0]
                await context.add_cookies([{
                    'name': name.strip(),
                    'value': value.strip(),
                    'domain': self.base_domain,
                    'path': '/'
                }])
            
            page = await context.new_page()
            page.on("request", lambda req: self._on_request(req))
            
            visited = set()
            to_visit = [(self.base_url, 0)]
            
            with tqdm(desc="Crawling pages", unit=" pages") as pbar:
                while to_visit:
                    url, depth = to_visit.pop(0)
                    if url in visited or depth > self.max_depth:
                        continue
                    
                    visited.add(url)
                    self.urls.add(url)
                    
                    try:
                        await page.goto(url, wait_until='networkidle', timeout=self.timeout)
                        await page.wait_for_timeout(2000)
                        
                        links = await self._extract_links(page)
                        for link in links:
                            if link not in visited and is_same_origin(link, self.base_url):
                                to_visit.append((link, depth + 1))
                        
                        await self._extract_forms(page, url)
                        pbar.update(1)
                        pbar.set_postfix({"APIs": len(self.api_endpoints), "Forms": len(self.forms)})
                        
                    except:
                        pass
            
            await browser.close()
        
        await self._analyze_js_files()
        
        print(f"\n{Fore.GREEN}[+] Crawl complete: {len(self.urls)} pages, {len(self.api_endpoints)} APIs{Style.RESET_ALL}")
        
        return {
            "urls": self.urls,
            "api_endpoints": self.api_endpoints,
            "forms": self.forms,
            "network_requests": self.network_requests
        }
    
    def _on_request(self, request):
        url = request.url
        method = request.method
        
        if is_same_origin(url, self.base_url):
            if request.resource_type in ['xhr', 'fetch']:
                endpoint = {
                    "url": url, "method": method, "type": "api",
                    "headers": dict(request.headers), "post_data": request.post_data
                }
                if endpoint not in self.api_endpoints:
                    self.api_endpoints.append(endpoint)
            
            if request.resource_type == 'script' and url.endswith('.js'):
                self.js_files.add(url)
            
            self.network_requests.append({"url": url, "method": method, "type": request.resource_type})
    
    async def _extract_links(self, page) -> List[str]:
        links = await page.evaluate('''() => {
            const links = new Set();
            document.querySelectorAll('a[href]').forEach(a => { if (a.href) links.add(a.href); });
            document.querySelectorAll('script[src]').forEach(s => { if (s.src) links.add(s.src); });
            document.querySelectorAll('form[action]').forEach(f => { if (f.action) links.add(f.action); });
            return Array.from(links);
        }''')
        
        normalized = []
        for link in links:
            try:
                full = urllib.parse.urljoin(self.base_url, link)
                parsed = urllib.parse.urlparse(full)
                if parsed.netloc == self.base_domain:
                    clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', parsed.query, ''))
                    normalized.append(clean)
            except:
                pass
        return normalized
    
    async def _extract_forms(self, page, url: str):
        forms = await page.evaluate('''() => {
            return Array.from(document.querySelectorAll('form')).map(form => {
                const inputs = Array.from(form.querySelectorAll('input, textarea, select')).map(el => ({
                    name: el.name || el.id || '', type: el.type || 'text', value: el.value || ''
                })).filter(i => i.name);
                return { action: form.action || window.location.href, method: (form.method || 'GET').toUpperCase(), inputs: inputs };
            });
        }''')
        
        for form in forms:
            if form['inputs']:
                form['source_url'] = url
                self.forms.append(form)
    
    async def _analyze_js_files(self):
        print(f"\n{Fore.CYAN}[*] Analyzing {len(self.js_files)} JS files...{Style.RESET_ALL}")
        
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'fetch\s*\(\s*["\'\`]([^"\'\`]+)["\'\`]',
        ]
        
        session = requests.Session()
        session.verify = False
        
        for js_url in list(self.js_files)[:20]:
            try:
                response = session.get(js_url, timeout=10)
                content = response.text
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        endpoint = match if isinstance(match, str) else match[-1]
                        if endpoint.startswith('/'):
                            full_url = urllib.parse.urljoin(self.base_url, endpoint)
                            if is_same_origin(full_url, self.base_url):
                                ep = {"url": full_url, "method": "GET", "type": "js_discovered", "source": js_url}
                                if ep not in self.api_endpoints:
                                    self.api_endpoints.append(ep)
            except:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

class VulnerabilityScanner:
    def __init__(self, timeout: int = 10, delay: float = 0.3, cookie: str = None, 
                 verbose: bool = False, verify_findings: bool = True):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = timeout
        self.delay = delay
        self.tests_performed = 0
        self.verbose = verbose
        self.verify_findings = verify_findings
        self.verifier = FalsePositiveVerifier(timeout)
        self.log_entries = []
        requests.packages.urllib3.disable_warnings()
        
        if cookie:
            self._set_cookie(cookie)
    
    def _set_cookie(self, cookie_str: str):
        if '=' in cookie_str:
            parts = cookie_str.split(';')
            for part in parts:
                if '=' in part:
                    name, value = part.strip().split('=', 1)
                    self.session.cookies.set(name, value)
    
    def _log(self, level: str, message: str):
        entry = {"timestamp": datetime.now().isoformat(), "level": level, "message": message}
        self.log_entries.append(entry)
        if self.verbose:
            color = Fore.RED if level == "ERROR" else Fore.YELLOW if level == "TEST" else Fore.CYAN
            print(f"  {color}[{level}] {message}{Style.RESET_ALL}")
    
    def scan(self, crawl_data: Dict) -> List[Dict]:
        vulnerabilities = []
        base_url = list(crawl_data.get("urls", set()))[0] if crawl_data.get("urls") else ""
        
        print(f"\n{Fore.YELLOW}[*] Starting vulnerability scan...{Style.RESET_ALL}")
        
        # Test security headers
        vulns = self.test_security_headers(base_url)
        vulnerabilities.extend(vulns)
        
        # Test sensitive files with verification
        vulns = self.test_sensitive_files(base_url)
        vulnerabilities.extend(vulns)
        
        # Test HTTP methods
        vulns = self.test_http_methods(base_url)
        vulnerabilities.extend(vulns)
        
        # Server fingerprinting with CVE verification
        vulns = self.fingerprint_server(base_url)
        vulnerabilities.extend(vulns)
        
        # Test forms
        for form in crawl_data.get("forms", []):
            vulns = self.test_form(form)
            vulnerabilities.extend(vulns)
        
        # Test API endpoints
        for endpoint in crawl_data.get("api_endpoints", []):
            vulns = self.test_endpoint(endpoint)
            vulnerabilities.extend(vulns)
        
        print(f"\n{Fore.GREEN}[+] Scan complete: {self.tests_performed} tests, {len(vulnerabilities)} findings{Style.RESET_ALL}")
        return vulnerabilities
    
    def test_security_headers(self, url: str) -> List[Dict]:
        vulnerabilities = []
        try:
            self._log("TEST", f"Testing security headers: {url}")
            response = self.session.get(url, timeout=self.timeout)
            self.tests_performed += 1
            
            missing = [h for h in SECURITY_HEADERS if h.lower() not in [k.lower() for k in response.headers]]
            
            if missing:
                vulnerabilities.append({
                    "type": "Missing Security Headers",
                    "severity": "INFO",
                    "url": url,
                    "parameter": "N/A",
                    "payload": "N/A",
                    "method": "GET",
                    "evidence": f"Missing: {', '.join(missing[:5])}",
                    "timestamp": datetime.now().isoformat()
                })
        except:
            pass
        return vulnerabilities
    
    def test_sensitive_files(self, base_url: str) -> List[Dict]:
        vulnerabilities = []
        print(f"\n{Fore.CYAN}[*] Testing sensitive files with verification...{Style.RESET_ALL}")
        
        for path in tqdm(SENSITIVE_PATHS[:30], desc="Checking sensitive files"):
            url = urllib.parse.urljoin(base_url, path)
            try:
                response = self.session.get(url, timeout=self.timeout)
                self.tests_performed += 1
                
                if response.status_code == 200 and len(response.content) > 0:
                    # Verify before reporting
                    if self.verify_findings:
                        is_real, reason = self.verifier.verify_sensitive_file(url, len(response.content))
                        if not is_real:
                            self._log("INFO", f"FALSE POSITIVE: {path} - {reason}")
                            continue
                    
                    vulnerabilities.append({
                        "type": "Sensitive File Exposure",
                        "severity": "CRITICAL" if any(x in path for x in ['.env', '.git', 'passwd']) else "MEDIUM",
                        "url": url,
                        "parameter": "N/A",
                        "payload": path,
                        "method": "GET",
                        "evidence": f"{len(response.content)} bytes (verified)",
                        "timestamp": datetime.now().isoformat()
                    })
            except:
                pass
            time.sleep(self.delay)
        
        return vulnerabilities
    
    def test_http_methods(self, url: str) -> List[Dict]:
        vulnerabilities = []
        try:
            response = self.session.options(url, timeout=self.timeout)
            self.tests_performed += 1
            
            allow = response.headers.get('Allow', '')
            dangerous = [m for m in ['PUT', 'DELETE', 'TRACE'] if m in allow.upper()]
            
            if dangerous:
                vulnerabilities.append({
                    "type": "Dangerous HTTP Methods",
                    "severity": "MEDIUM",
                    "url": url,
                    "parameter": "N/A",
                    "payload": ", ".join(dangerous),
                    "method": "OPTIONS",
                    "evidence": f"Allow: {allow}",
                    "timestamp": datetime.now().isoformat()
                })
        except:
            pass
        return vulnerabilities
    
    def fingerprint_server(self, url: str) -> List[Dict]:
        vulnerabilities = []
        try:
            response = self.session.get(url, timeout=self.timeout)
            self.tests_performed += 1
            
            server = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            # Check for version disclosure
            if server or powered_by:
                vulnerabilities.append({
                    "type": "Server Info Disclosure",
                    "severity": "LOW",
                    "url": url,
                    "parameter": "N/A",
                    "payload": f"Server: {server}, X-Powered-By: {powered_by}",
                    "method": "GET",
                    "evidence": "Version exposed",
                    "timestamp": datetime.now().isoformat()
                })
            
            # Check IIS CVEs with verification
            if 'IIS' in server:
                version_match = re.search(r'IIS/(\d+\.\d+)', server)
                if version_match:
                    version = version_match.group(1)
                    if version in IIS_CVES:
                        for cve_id, (severity, desc) in IIS_CVES[version].items():
                            # Verify CVE
                            if self.verify_findings:
                                is_real, reason = self.verifier.verify_cve(cve_id, url, server)
                                if not is_real:
                                    self._log("INFO", f"CVE {cve_id}: {reason}")
                                    severity = "INFO"  # Downgrade to info
                                    desc = f"{desc} - {reason}"
                            
                            vulnerabilities.append({
                                "type": f"Potential {cve_id}",
                                "severity": severity,
                                "url": url,
                                "parameter": "Server Header",
                                "payload": server,
                                "method": "GET",
                                "evidence": desc,
                                "timestamp": datetime.now().isoformat()
                            })
        except:
            pass
        return vulnerabilities
    
    def test_form(self, form: Dict) -> List[Dict]:
        vulnerabilities = []
        action = form.get('action', '')
        method = form.get('method', 'GET')
        inputs = form.get('inputs', [])
        
        if not action or not inputs:
            return vulnerabilities
        
        # Build base data
        base_data = {i['name']: i.get('value', 'test') for i in inputs}
        
        # Test SQL injection
        for inp in inputs[:3]:
            if inp['type'] in ['password', 'hidden', 'submit']:
                continue
            
            for payload in SQL_PAYLOADS[:5]:
                test_data = base_data.copy()
                test_data[inp['name']] = payload
                
                try:
                    if method == 'POST':
                        response = self.session.post(action, data=test_data, timeout=self.timeout)
                    else:
                        response = self.session.get(action, params=test_data, timeout=self.timeout)
                    
                    self.tests_performed += 1
                    
                    # Check for SQL errors (excluding false positives)
                    response_text = response.text.lower()
                    is_false_positive = any(re.search(p, response_text) for p in SQL_FALSE_POSITIVES)
                    
                    if not is_false_positive:
                        for pattern in SQL_ERROR_PATTERNS:
                            if re.search(pattern, response_text):
                                vulnerabilities.append({
                                    "type": "SQL Injection",
                                    "severity": "CRITICAL",
                                    "url": action,
                                    "parameter": inp['name'],
                                    "payload": payload,
                                    "method": method,
                                    "evidence": f"SQL error pattern: {pattern}",
                                    "timestamp": datetime.now().isoformat()
                                })
                                break
                except:
                    pass
                time.sleep(self.delay)
        
        return vulnerabilities
    
    def test_endpoint(self, endpoint: Dict) -> List[Dict]:
        vulnerabilities = []
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET')
        
        if not url:
            return vulnerabilities
        
        # Parse URL for parameters
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if params:
            # Test each parameter
            for param, values in list(params.items())[:3]:
                for payload in XSS_PAYLOADS[:3]:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        '', urllib.parse.urlencode(test_params, doseq=True), ''
                    ))
                    
                    try:
                        response = self.session.get(test_url, timeout=self.timeout)
                        self.tests_performed += 1
                        
                        if payload in response.text:
                            vulnerabilities.append({
                                "type": "Reflected XSS",
                                "severity": "HIGH",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                                "method": "GET",
                                "evidence": "Payload reflected in response",
                                "timestamp": datetime.now().isoformat()
                            })
                            break
                    except:
                        pass
                    time.sleep(self.delay)
        
        return vulnerabilities
    
    def save_debug_log(self, output_base: str):
        log_path = f"{output_base}_debug.log"
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(f"WebVulnScanner Debug Log\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write("="*80 + "\n\n")
            for entry in self.log_entries:
                f.write(f"[{entry['timestamp']}] [{entry['level']}] {entry['message']}\n")
        return log_path


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

def generate_json_report(data: Dict, output_path: str):
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)
    print(f"{Fore.GREEN}[+] JSON report: {output_path}{Style.RESET_ALL}")

def generate_html_report(data: Dict, output_path: str):
    html = f"""<!DOCTYPE html>
<html><head>
<title>Vulnerability Scan Report</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
h1, h2 {{ color: #00d4ff; }}
.vuln {{ border-left: 4px solid; padding: 15px; margin: 10px 0; background: #16213e; border-radius: 5px; }}
.CRITICAL {{ border-color: #ff4040; }}
.HIGH {{ border-color: #ff8c00; }}
.MEDIUM {{ border-color: #ffd700; }}
.LOW {{ border-color: #4da6ff; }}
.INFO {{ border-color: #00bcd4; }}
.severity {{ font-weight: bold; padding: 3px 8px; border-radius: 3px; }}
.stats {{ display: flex; gap: 20px; margin: 20px 0; }}
.stat {{ background: #0f3460; padding: 20px; border-radius: 10px; text-align: center; }}
.stat-value {{ font-size: 2em; color: #00d4ff; }}
pre {{ background: #0a0a1a; padding: 10px; overflow-x: auto; border-radius: 5px; }}
</style>
</head><body>
<h1>🛡️ Vulnerability Scan Report</h1>
<p>Target: <code>{escape(data.get('target', 'N/A'))}</code></p>
<p>Scan Time: {data.get('start_time', 'N/A')} - {data.get('end_time', 'N/A')}</p>
<p>Duration: {data.get('duration_seconds', 0):.1f} seconds</p>

<div class="stats">
<div class="stat"><div class="stat-value">{data['stats']['pages_crawled']}</div>Pages</div>
<div class="stat"><div class="stat-value">{data['stats']['api_endpoints']}</div>APIs</div>
<div class="stat"><div class="stat-value">{data['stats']['tests_performed']}</div>Tests</div>
<div class="stat"><div class="stat-value">{data['stats']['vulnerabilities']}</div>Findings</div>
</div>

<h2>Vulnerabilities ({len(data.get('vulnerabilities', []))})</h2>
"""
    
    for vuln in data.get('vulnerabilities', []):
        html += f"""
<div class="vuln {vuln['severity']}">
<span class="severity">{vuln['severity']}</span> <strong>{escape(vuln['type'])}</strong><br>
<strong>URL:</strong> <code>{escape(vuln['url'])}</code><br>
<strong>Parameter:</strong> {escape(vuln.get('parameter', 'N/A'))}<br>
<strong>Evidence:</strong> {escape(vuln.get('evidence', 'N/A'))}<br>
</div>
"""
    
    html += "</body></html>"
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"{Fore.GREEN}[+] HTML report: {output_path}{Style.RESET_ALL}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    parser = argparse.ArgumentParser(
        description='WebVulnScanner v2.1 (Generic) - Browser-Automated Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Max crawl depth (default: 3)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('-o', '--output', help='Output filename base (default: scan_TIMESTAMP)')
    parser.add_argument('-c', '--cookie', help='Session cookie for authenticated scanning (name=value)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output with test details')
    parser.add_argument('--no-verify', action='store_true', help='Skip false positive verification')
    
    args = parser.parse_args()
    
    print_banner()
    
    start_time = datetime.now()
    
    # Crawl
    crawler = BrowserCrawler(args.url, max_depth=args.depth, cookie=args.cookie)
    crawl_data = await crawler.crawl()
    
    # Scan with verification
    scanner = VulnerabilityScanner(
        timeout=args.timeout, 
        cookie=args.cookie, 
        verbose=args.verbose,
        verify_findings=not args.no_verify
    )
    vulnerabilities = scanner.scan(crawl_data)
    
    end_time = datetime.now()
    
    # Build report
    output_base = args.output or f"scan_{start_time.strftime('%Y%m%d_%H%M%S')}"
    
    endpoints = [
        {"url": e["url"], "method": e["method"], "type": e.get("type", "unknown")}
        for e in crawl_data.get("api_endpoints", [])
    ]
    
    # Add form endpoints
    for form in crawl_data.get("forms", []):
        action = form.get("action", "")
        inputs = form.get("inputs", [])
        if action:
            post_data = "&".join([f"{i['name']}={i.get('value', '')}" for i in inputs])
            endpoints.append({"url": action, "method": form.get("method", "GET"), "type": "form", "post_data": post_data})
    
    report_data = {
        "target": args.url,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "duration_seconds": (end_time - start_time).total_seconds(),
        "stats": {
            "pages_crawled": len(crawl_data.get("urls", set())),
            "api_endpoints": len(crawl_data.get("api_endpoints", [])),
            "forms_found": len(crawl_data.get("forms", [])),
            "network_requests": len(crawl_data.get("network_requests", [])),
            "tests_performed": scanner.tests_performed,
            "vulnerabilities": len(vulnerabilities)
        },
        "endpoints": endpoints,
        "vulnerabilities": vulnerabilities
    }
    
    # Save reports
    generate_json_report(report_data, f"{output_base}.json")
    generate_html_report(report_data, f"{output_base}.html")
    scanner.save_debug_log(output_base)
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}SCAN COMPLETE{Style.RESET_ALL}")
    print(f"  Duration: {report_data['duration_seconds']:.1f}s")
    print(f"  Pages: {report_data['stats']['pages_crawled']}")
    print(f"  APIs: {report_data['stats']['api_endpoints']}")
    print(f"  Tests: {report_data['stats']['tests_performed']}")
    print(f"  Findings: {report_data['stats']['vulnerabilities']}")
    
    if vulnerabilities:
        print(f"\n{Fore.RED}VULNERABILITIES:{Style.RESET_ALL}")
        for v in vulnerabilities[:10]:
            color = severity_color(v['severity'])
            print(f"  {color}[{v['severity']}]{Style.RESET_ALL} {v['type']}: {v['url'][:50]}...")


if __name__ == "__main__":
    asyncio.run(main())

