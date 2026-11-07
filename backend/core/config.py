import os
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).parent.parent / ".env")

# Gemini
GEMINI_API_KEYS = [k.strip() for k in os.getenv("GEMINI_API_KEYS", "").split(",") if k.strip()]
GEMINI_API_KEY = GEMINI_API_KEYS[0] if GEMINI_API_KEYS else os.getenv("GEMINI_API_KEY", "")
if GEMINI_API_KEY and not os.environ.get("GEMINI_API_KEY"):
    os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY
PRIMARY_MODEL = os.getenv("PRIMARY_MODEL", "gemini-2.5-flash")

# PSU AI (read from multiple possible env key names for compatibility)
PSU_AI_API_KEY = os.getenv("PSU_AI_API_KEY", "") or os.getenv("OPENAI_API_KEY", "")
PSU_AI_BASE_URL = os.getenv("PSU_AI_BASE_URL", "") or os.getenv("OPENAI_BASE_URL", "https://ai.psu.blue/v1")
PSU_AI_MODEL = os.getenv("PSU_AI_MODEL", "") or os.getenv("PSU_MODEL", "PSU-LLM/psu-gemma")
PREFERRED_AI_PROVIDER = os.getenv("PREFERRED_AI_PROVIDER", "gemini")

# Models and Upload dir
MODELS_DIR = Path(__file__).parent.parent / "models"
AIR_GAPPED_MODE = os.getenv("AIR_GAPPED", "").lower() in ("1", "true", "yes") or os.getenv("SHADOWCAT_OFFLINE", "").lower() in ("1", "true", "yes")
try:
    UPLOAD_DIR = Path.home() / ".shadowsolve" / "uploads"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
except Exception:
    import tempfile
    UPLOAD_DIR = Path(tempfile.gettempdir()) / f"shadowsolve_uploads_{os.getuid() if hasattr(os, 'getuid') else 'user'}"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def prune_old_uploads(max_age_hours: int = 48) -> int:
    """Removes forensic uploads older than max_age_hours to prevent disk exhaustion."""
    import time
    count = 0
    now = time.time()
    cutoff = now - (max_age_hours * 3600)
    try:
        if UPLOAD_DIR.exists():
            for item in UPLOAD_DIR.iterdir():
                if item.is_file() and item.stat().st_mtime < cutoff:
                    try:
                        item.unlink()
                        count += 1
                    except Exception:
                        pass
    except Exception:
        pass
    return count
