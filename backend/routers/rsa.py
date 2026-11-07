import sys
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Union

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.voice import announce_flag

router = APIRouter()

def _parse_bigint(val: Optional[Union[int, str]], name: str) -> Optional[int]:
    if val is None:
        return None
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid numeric value for {name}: '{s}'")

class RSARequest(BaseModel):
    n: Union[int, str]
    e: Union[int, str]
    c: Optional[Union[int, str]] = None

@router.post("/attack")
def rsa_attack(req: RSARequest):
    """Run RSA attacks: small N factoring, Wiener, cube root (e=3), FactorDB with BigInt precision via threadpool."""
    try:
        parsed_n = _parse_bigint(req.n, "modulus n")
        parsed_e = _parse_bigint(req.e, "exponent e")
        parsed_c = _parse_bigint(req.c, "ciphertext c")

        if parsed_n is None or parsed_e is None:
            raise HTTPException(status_code=400, detail="Modulus 'n' and Exponent 'e' are required.")

        from core.ctf_agent import rsa_attack as _rsa
        result = _rsa(parsed_n, parsed_e, parsed_c)
        if result.get("flags"):
            announce_flag(result["flags"][0])
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
