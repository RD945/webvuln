# WebVulnScanner v2.1

## Browser-Automated Web Vulnerability Scanner

A comprehensive Python-based web vulnerability scanner with browser automation, JavaScript rendering, and authenticated scanning support. Includes built-in false positive verification.

---

## Features

### Core Capabilities
- Browser-based crawling using Playwright (Chromium)
- JavaScript rendering for React/Next.js/SPA applications
- Network request interception and API endpoint discovery
- Authenticated scanning with session cookie support
- **Built-in false positive verification** (soft 404 detection, content validation)
- Detailed debug logging for test verification

### Vulnerability Detection Modules

| Module | Description |
|--------|-------------|
| `sqli` | SQL Injection (error-based, time-based blind) |
| `xss` | Cross-Site Scripting (reflected, WAF bypass) |
| `lfi` | Local File Inclusion (null byte, PHP wrappers) |
| `rce` | Remote Code Execution |
| `ssrf` | Server-Side Request Forgery (cloud metadata) |
| `headers` | Missing security headers |
| `nextjs` | Next.js CVEs (CVE-2024-34351, CVE-2025-29927) |
| `react` | React-specific vulnerabilities |
| `recon` | Reconnaissance (CORS, sensitive files, HTTP methods) |
| `crlf` | CRLF Injection |
| `exploits` | JWT, OAuth, cache poisoning, CDN detection |
| `erp` | IDOR, mass assignment, jQuery, DDoS stress |

---

## Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Install Dependencies
```bash
pip install requests beautifulsoup4 colorama tqdm lxml playwright
playwright install chromium
```

---

## Usage

### Basic Scan
```bash
python webvulnscanner_generic.py https://target.com
```

### Authenticated Scan
```bash
# With session cookie
python webvulnscanner_generic.py https://target.com -c "session=abc123xyz"

# Multiple cookies
python webvulnscanner_generic.py https://target.com -c "session=abc; token=xyz"
```

### Skip False Positive Verification (Faster)
```bash
python webvulnscanner_generic.py https://target.com --no-verify
```

### Verbose Mode (Debug Output)
```bash
python webvulnscanner_generic.py https://target.com -v
```

---

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `url` | Target URL (required) | - |
| `-d, --depth` | Crawl depth | 3 |
| `-t, --timeout` | Request timeout in seconds | 10 |
| `-o, --output` | Output file base name | scan_TIMESTAMP |
| `-c, --cookie` | Session cookie for authenticated scanning | - |
| `-v, --verbose` | Show detailed test output | false |
| `--no-verify` | Skip false positive verification | false |

---

## Output Files

After each scan, three files are generated:

| File | Content |
|------|---------|
| `scan_*.json` | Structured JSON results |
| `scan_*.html` | Visual HTML report |
| `scan_*_debug.log` | Detailed test execution log |

---

## False Positive Verification

v2.1 includes automatic verification to reduce false positives:

### Sensitive File Detection
- Checks HTTP status codes (real 404 vs soft 404)
- Validates content patterns for `.env` files
- Checks for actual git metadata in `.git` responses
- Detects HTML 404 pages returned with 200 status

### CVE Verification
- CVE-2022-21907 (IIS): Checks for HTTP Trailer Support
- Other CVEs: Marked as "needs verification"

---

## Payloads Database

### SQL Injection
- Basic: `' OR '1'='1`, `admin'--`, `' UNION SELECT NULL--`
- Time-based: `SLEEP(5)`, `WAITFOR DELAY`, `pg_sleep(5)`

### XSS
- Standard: `<script>alert()</script>`, `<img onerror>`
- WAF bypass: Unicode, mixed case, HTML entities

### SSRF (Cloud Metadata)
- AWS: `http://169.254.169.254/latest/meta-data/`
- Azure: `http://169.254.169.254/metadata/instance`
- GCP: `http://metadata.google.internal/computeMetadata/v1/`

### LFI
- Basic: `../../etc/passwd`
- Bypass: null byte, double encoding, PHP wrappers

---

## Server CVE Detection

The scanner checks server version headers against known CVEs:

### Nginx CVEs
| Version | CVE | Severity | Description |
|---------|-----|----------|-------------|
| 1.27.x | CVE-2025-23419 | HIGH | SSL session reuse |
| 1.26.x | CVE-2024-32760 | HIGH | HTTP/3 worker crash |
| 1.20.x | CVE-2021-23017 | CRITICAL | DNS resolver RCE |

### Apache CVEs
| Version | CVE | Severity | Description |
|---------|-----|----------|-------------|
| 2.4.49 | CVE-2021-41773 | CRITICAL | Path traversal + RCE |
| 2.4.50 | CVE-2021-42013 | CRITICAL | Path traversal bypass |

### IIS CVEs
| Version | CVE | Severity | Description |
|---------|-----|----------|-------------|
| 10.0 | CVE-2022-21907 | CRITICAL* | HTTP Protocol Stack RCE |

*Requires HTTP Trailer Support to be enabled - scanner verifies this automatically.

---

## Architecture

```
webvulnscanner_generic.py
    |
    +-- BrowserCrawler (Playwright)
    |       - JavaScript rendering
    |       - Network interception
    |       - Endpoint discovery
    |
    +-- FalsePositiveVerifier
    |       - Soft 404 detection
    |       - Content validation
    |       - CVE verification
    |
    +-- VulnerabilityScanner
    |       - Authenticated requests
    |       - Payload injection
    |       - Response analysis
    |
    +-- ReportGenerator
            - JSON output
            - HTML report
            - Debug log
```

---

## Additional Tools

| Script | Purpose |
|--------|---------|
| `scan_verifier.py` | Verify existing scan results for false positives |
| `cve_2022_21907_verifier.py` | Deep verification for IIS HTTP.sys vulnerability |

---

## Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║  WebVulnScanner v2.1 (Generic) - With False Positive Detection   ║
╚══════════════════════════════════════════════════════════════════╝

[*] Starting browser-based crawl of https://example.com
[+] Crawl complete: 15 pages, 42 APIs

[*] Testing sensitive files with verification...
  [INFO] FALSE POSITIVE: /.env - Soft 404 - page content indicates not found
  [INFO] FALSE POSITIVE: /.git/config - No git metadata patterns found

[+] Scan complete: 250 tests, 3 findings

SCAN COMPLETE
  Duration: 45.2s
  Pages: 15
  APIs: 42
  Tests: 250
  Findings: 3

VULNERABILITIES:
  [INFO] Missing Security Headers: https://example.com...
  [MEDIUM] Dangerous HTTP Methods: https://example.com...
```

---

## Legal Disclaimer

This tool is intended for authorized security testing only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. Always obtain proper authorization before conducting security assessments.

---

## Changelog

### v2.1 (December 2025)
- Added `FalsePositiveVerifier` class
- Soft 404 detection for sensitive file checks
- CVE verification (HTTP Trailer Support for IIS)
- New `--no-verify` flag
- Removed hardcoded credentials

### v2.0
- Browser-based crawling with Playwright
- JavaScript rendering support
- Network request interception
- Authenticated scanning
