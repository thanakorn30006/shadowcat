import sys
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, List, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

router = APIRouter()

class WebRequest(BaseModel):
    url: str
    headers: Optional[Dict[str, str]] = {}
    cookies: Optional[Dict[str, str]] = {}

class WafProbeRequest(BaseModel):
    url: str

class MutatePayloadRequest(BaseModel):
    payload: str

class JsAnalysisRequest(BaseModel):
    url: Optional[str] = ""
    raw_code: Optional[str] = ""

# NOTE: declared as a plain `def` (not `async def`) on purpose — web_hunt_flag uses
# the blocking `requests` library, so FastAPI runs this handler in a threadpool and
# it never stalls the event loop / other concurrent requests.
@router.post("/hunt")
def web_hunt(req: WebRequest):
    """Hunt for CTF flags in a web target: source, headers, common paths, payloads."""
    try:
        from core.ctf_agent import web_hunt_flag
        result = web_hunt_flag(req.url, req.headers or {}, req.cookies or {})
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/waf-detect")
async def detect_waf_endpoint(req: WafProbeRequest):
    """Probe target URL and fingerprint active Web Application Firewalls (Cloudflare, AWS, ModSec, etc.)."""
    try:
        from core.waf_engine import probe_waf
        result = await probe_waf(req.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/mutate-payload")
def mutate_payload_endpoint(req: MutatePayloadRequest):
    """Generate high-yield WAF evasion variants (URL encoding, comment splitting, case jittering, space bypass)."""
    try:
        from core.waf_engine import mutate_payload_variants
        variants = mutate_payload_variants(req.payload)
        return {"variants": variants, "count": len(variants)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze-js")
async def analyze_js_endpoint(req: JsAnalysisRequest):
    """Extract hidden API endpoints, routes, tokens, and leaked secrets from JavaScript assets."""
    try:
        from core.js_hunter import analyze_target_js
        result = await analyze_target_js(req.url or "", req.raw_code or "")
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------------------------------------
# Burp Suite-Grade Repeater & Active Vulnerability Scanner
# -------------------------------------------------------------
class RepeaterRequest(BaseModel):
    url: str
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, str]] = {}
    cookies: Optional[Dict[str, str]] = {}
    body: Optional[str] = None
    follow_redirects: Optional[bool] = True

class ScannerRequest(BaseModel):
    url: str

@router.post("/repeater")
async def burp_repeater_endpoint(req: RepeaterRequest):
    """Sends arbitrary HTTP request and returns full response headers, body, latency and flags."""
    from core.burp_engine import burp_repeater_send
    return await burp_repeater_send(
        url=req.url,
        method=req.method or "GET",
        headers=req.headers,
        cookies=req.cookies,
        body=req.body,
        follow_redirects=req.follow_redirects if req.follow_redirects is not None else True
    )

@router.post("/scan-vulns")
async def burp_scanner_endpoint(req: ScannerRequest):
    """Actively probes target for LFI, SSTI, SQLi errors, exposed sensitive files, and missing headers."""
    from core.burp_engine import scan_target_vulnerabilities
    return await scan_target_vulnerabilities(req.url)
