import sys
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.voice import announce_flag

router = APIRouter()

class NetcatRequest(BaseModel):
    host: str
    port: int

@router.post("/solve")
def netcat_solve(req: NetcatRequest):
    """Connect to a CTF netcat challenge and auto-solve it via threadpool."""
    try:
        from core.ctf_agent import netcat_solve_challenge
        result = netcat_solve_challenge(req.host, req.port)
        if result.get("flags_found"):
            announce_flag(result["flags_found"][0])
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
