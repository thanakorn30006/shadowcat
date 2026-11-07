import sys
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

router = APIRouter()

class WriteupRequest(BaseModel):
    query: str
    top_k: int = 3

@router.post("/search")
def search_writeups(req: WriteupRequest):
    """Search CTF writeup knowledge base for similar challenges and hints via threadpool."""
    try:
        from core.ctf_ml import get_search_engine
        engine = get_search_engine()
        results = engine.search(req.query, top_k=req.top_k)
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
