import sys, os
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.license_engine import (
    verify_license_content,
    get_machine_id,
    MASTER_PUBLIC_KEY_HEX
)

router = APIRouter()

class LicenseActivationRequest(BaseModel):
    token: Optional[str] = ""
    license_content: Optional[str] = ""

def detect_license():
    machine_id = get_machine_id()

    # 1. Check environment variable
    env_content = os.environ.get("SHADOWCAT_LICENSE") or os.environ.get("SHADOWCAT_KEY")
    if env_content and env_content.strip():
        valid, reason, meta = verify_license_content(env_content)
        if valid and meta.get("pro_features"):
            return {
                "tier": meta.get("tier", "PRO_OPERATOR"),
                "status": "ACTIVE_OFFLINE",
                "signature_valid": True,
                "expires": "NEVER",
                "channel": "environment_variable",
                "holder": meta.get("holder", "Operator"),
                "token": meta.get("token", "")[:18] + "...",
                "hardware_id": meta.get("hardware_id", "ANY"),
                "machine_id": machine_id,
                "pro_features": True
            }

    # 2. Check local file locations
    search_paths = [
        Path.home() / "shadowcat" / "shadowcat.lic",
        Path.home() / ".shadowcat" / "shadowcat.lic",
        Path(__file__).resolve().parent.parent.parent / "shadowcat.lic",
        Path.cwd() / "shadowcat.lic"
    ]

    for p in search_paths:
        if p.is_file():
            try:
                content = p.read_text(encoding="utf-8")
                valid, reason, meta = verify_license_content(content)
                if valid and meta.get("pro_features"):
                    return {
                        "tier": meta.get("tier", "PRO_OPERATOR"),
                        "status": "ACTIVE_OFFLINE",
                        "signature_valid": True,
                        "expires": "NEVER",
                        "channel": f"file:{p.name}",
                        "file_path": str(p),
                        "holder": meta.get("holder", "Operator"),
                        "hardware_id": meta.get("hardware_id", "ANY"),
                        "machine_id": machine_id,
                        "pro_features": True
                    }
                elif not valid and "BEGIN SHADOWCAT LICENSE" in content:
                    return {
                        "tier": "COMMUNITY",
                        "status": "SIGNATURE_INVALID_OR_TAMPERED",
                        "signature_valid": False,
                        "reason": reason,
                        "file_path": str(p),
                        "machine_id": machine_id,
                        "pro_features": False,
                        "upgrade_url": "https://thanakorn30006.github.io/pricing.html"
                    }
            except Exception:
                pass

    return {
        "tier": "COMMUNITY",
        "status": "ACTIVE_OFFLINE",
        "signature_valid": True,
        "expires": "NEVER",
        "channel": "built_in_open_core",
        "machine_id": machine_id,
        "pro_features": False,
        "upgrade_url": "http://localhost:3333/pricing.html"
    }

@router.get("/status")
def get_license_status():
    return detect_license()

@router.get("/machine-id")
def get_machine_hwid():
    """Returns local Machine Hardware ID for node-locked license activation."""
    return {
        "hwid": get_machine_id(),
        "status": "OK"
    }

@router.post("/activate")
def activate_license(req: LicenseActivationRequest):
    content = (req.license_content or req.token or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Must provide license file content")

    valid, reason, meta = verify_license_content(content)
    if not valid:
        raise HTTPException(
            status_code=400,
            detail=f"Cryptographic verification failed: {reason}"
        )

    target_dir = Path.home() / "shadowcat"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / "shadowcat.lic"
    target_file.write_text(content, encoding="utf-8")

    return {
        "success": True,
        "message": "License successfully verified with Ed25519 signature and installed.",
        "tier": meta.get("tier", "PRO_OPERATOR"),
        "holder": meta.get("holder", "Operator"),
        "hardware_id": meta.get("hardware_id", "ANY"),
        "file_path": str(target_file),
        "status": "ACTIVE_OFFLINE"
    }
