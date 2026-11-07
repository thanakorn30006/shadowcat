import sys
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

from typing import Optional
from core.config import AIR_GAPPED_MODE

router = APIRouter()

class HashRequest(BaseModel):
    hash: str
    offline_only: Optional[bool] = False

@router.get("/stats")
def hash_stats():
    """Returns offline wordlist count and supported algorithms."""
    from core.offline_wordlist_cracker import get_wordlist_stats
    return get_wordlist_stats()

@router.post("/crack")
def crack_hash(req: HashRequest):
    """Crack hash using offline high-yield RockYou wordlist first, then fallback to local DB & APIs."""
    try:
        from core.offline_wordlist_cracker import crack_offline_hash
        offline_hit = crack_offline_hash(req.hash)
        if offline_hit and offline_hit.get("cracked"):
            return offline_hit

        # OpSec Air-Gapped Enforcement
        if req.offline_only or AIR_GAPPED_MODE:
            return {
                "cracked": False,
                "hash": req.hash,
                "source": "offline_dictionary",
                "hint": "Hash not found in offline high-yield wordlist. Outbound queries blocked by Air-Gapped Mode.",
                "air_gapped": True
            }

        from core.ctf_ml import ctf_hash_crack
        result = ctf_hash_crack(req.hash)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
