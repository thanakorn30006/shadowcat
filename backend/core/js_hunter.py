from __future__ import annotations

import re
import os.path
import urllib.parse
from html.parser import HTMLParser
from typing import Dict, List, Set, Any
import httpx

_API_REGEXES = [
    re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|delete|patch|request)|this\.\$?http\.(?:get|post|put|delete))\s*\(\s*[`'"]([^`'"]{4,})[`'"]""",
        re.IGNORECASE,
    ),
    re.compile(r"""url\s*:\s*[`'"]([^`'"<>\s]{4,})[`'"]"""),
    re.compile(r"""(?:path|route|endpoint)\s*:\s*[`'"]([^`'"<>\s]{2,})[`'"]"""),
    re.compile(
        r"""[`'"](/(?:api|rest|v\d+|graphql|rpc|auth|admin|account|user|dashboard|service|public|private|login|register|flag|secret|config)[^`'"<>\s]*)[`'"]"""
    ),
    re.compile(
        r"""(?:baseURL|BASE_URL|API_URL|API_BASE|BASE_PATH|TARGET_URL)\s*[=:]\s*[`'"]([^`'"<>\s]{4,})[`'"]"""
    ),
]

_SECRET_PATTERNS = [
    ("JWT Token", re.compile(r"""\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b""")),
    ("AWS Access Key ID", re.compile(r"""\b(AKIA[0-9A-Z]{16})\b""")),
    ("Bearer Authorization Header", re.compile(r"""(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})""")),
    ("Private Key Block", re.compile(r"""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----""")),
    ("GitHub Personal Token", re.compile(r"""\b(gh[pous]_[a-zA-Z0-9]{36,})\b""")),
    ("Generic API Key Literal", re.compile(r"""(?i)(?:api[_-]?key|secret|token|auth_token|client_secret)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,64})["']""")),
    ("Internal Private IPv4", re.compile(r"""\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b""")),
    ("CTF Flag Pattern", re.compile(r"""(?:flag|FLAG|ctf|CTF|THREAT|picoCTF)\{[^}\n\r]+\}""")),
]

_SKIP_EXTENSIONS = frozenset(
    {".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"}
)

class _ScriptSrcParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.script_srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        a = dict(attrs)
        src = a.get("src")
        if src and not src.startswith("data:"):
            self.script_srcs.append(src)

def extract_endpoints_from_code(js_source: str) -> List[str]:
    """Find unique API endpoints and route paths in JavaScript source."""
    found: Set[str] = set()
    for pattern in _API_REGEXES:
        for m in pattern.finditer(js_source):
            path = m.group(1).strip()
            if path.startswith("/") and len(path) >= 3 and " " not in path and "\n" not in path:
                _, ext = os.path.splitext(path.split("?")[0])
                if ext.lower() not in _SKIP_EXTENSIONS:
                    found.add(path)
    return sorted(found)

def extract_secrets_from_code(js_source: str) -> List[Dict[str, str]]:
    """Scan JavaScript text for API keys, tokens, credentials, and sensitive markers."""
    findings: List[Dict[str, str]] = []
    seen: Set[str] = set()

    for label, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(js_source):
            val = match.group(0).strip()
            if val not in seen and len(val) < 250:
                seen.add(val)
                findings.append({
                    "type": label,
                    "value": val,
                })
    return findings

async def analyze_target_js(url: str, raw_code: str = "") -> Dict[str, Any]:
    """Analyze JavaScript from raw code or by scraping a target URL."""
    endpoints: Set[str] = set()
    secrets: List[Dict[str, str]] = []
    analyzed_scripts: List[str] = []

    if raw_code and raw_code.strip():
        endpoints.update(extract_endpoints_from_code(raw_code))
        secrets.extend(extract_secrets_from_code(raw_code))
        analyzed_scripts.append("Direct Raw Input")

    if url and url.strip():
        clean_url = url.strip()
        if not clean_url.startswith(("http://", "https://")):
            clean_url = "http://" + clean_url

        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                resp = await client.get(clean_url, follow_redirects=True)
                
                # If target is directly a .js file
                if clean_url.endswith(".js") or "javascript" in resp.headers.get("content-type", ""):
                    analyzed_scripts.append(clean_url)
                    endpoints.update(extract_endpoints_from_code(resp.text))
                    secrets.extend(extract_secrets_from_code(resp.text))
                else:
                    # Parse HTML to find linked script tags
                    parser = _ScriptSrcParser()
                    parser.feed(resp.text)
                    
                    # Also analyze inline script tags from the HTML itself
                    endpoints.update(extract_endpoints_from_code(resp.text))
                    secrets.extend(extract_secrets_from_code(resp.text))
                    analyzed_scripts.append(f"{clean_url} (Inline DOM Scripts)")

                    # Concurrently fetch external scripts
                    for src in parser.script_srcs[:12]:
                        abs_script = urllib.parse.urljoin(clean_url, src)
                        try:
                            s_resp = await client.get(abs_script, timeout=6.0)
                            if s_resp.status_code == 200:
                                analyzed_scripts.append(abs_script)
                                endpoints.update(extract_endpoints_from_code(s_resp.text))
                                secrets.extend(extract_secrets_from_code(s_resp.text))
                        except Exception:
                            continue
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "endpoints": sorted(endpoints),
                "secrets": secrets,
                "analyzed_scripts": analyzed_scripts,
            }

    flags_found = [s["value"] for s in secrets if s.get("type") == "CTF Flag Pattern"]

    return {
        "success": True,
        "endpoints_count": len(endpoints),
        "secrets_count": len(secrets),
        "endpoints": sorted(endpoints),
        "secrets": secrets,
        "flags_found": list(set(flags_found)),
        "analyzed_scripts": analyzed_scripts,
    }
