import sys
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

router = APIRouter()

class ClassifyRequest(BaseModel):
    description: str

@router.post("")
def classify_challenge(req: ClassifyRequest):
    """Use ML (TF-IDF + Logistic Regression) to classify a CTF challenge description via threadpool."""
    try:
        from core.ctf_ml import ctf_classify
        result = ctf_classify(req.description)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
