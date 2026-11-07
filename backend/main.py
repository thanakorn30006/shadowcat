from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from routers import forensics, crypto, rsa, hash_crack, web, netcat, classify, writeup, chat, binary, jwt_tool, license
from core.config import prune_old_uploads

app = FastAPI(
    title="SHADOW CAT API",
    description="Cyber Operations Suite — Forensics · Crypto · Web · Pwn · Rev · Misc",
    version="1.2.0",
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Whitelist local application origins for safe execution and anti-SSRF pivot
ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3333",
    "http://127.0.0.1:3333",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "tauri://localhost",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

app.include_router(forensics.router, prefix="/api/forensics", tags=["Forensics"])
app.include_router(crypto.router,    prefix="/api/crypto",    tags=["Crypto"])
app.include_router(rsa.router,       prefix="/api/rsa",       tags=["RSA"])
app.include_router(hash_crack.router,prefix="/api/hash",      tags=["Hash"])
app.include_router(web.router,       prefix="/api/web",       tags=["Web"])
app.include_router(jwt_tool.router,  prefix="/api/jwt",       tags=["JWT Studio"])
app.include_router(binary.router,    prefix="/api/binary",    tags=["Binary & Pwn"])
app.include_router(netcat.router,    prefix="/api/netcat",    tags=["Netcat"])
app.include_router(classify.router,  prefix="/api/classify",  tags=["Classify"])
app.include_router(writeup.router,   prefix="/api/writeup",   tags=["Writeup"])
app.include_router(chat.router,      prefix="/api/chat",      tags=["Chat"])
app.include_router(license.router,   prefix="/api/license",   tags=["License"])

@app.on_event("startup")
def startup_event():
    # Clean stale uploads older than 48 hours to conserve disk space
    prune_old_uploads(max_age_hours=48)

@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    return {"status": "ok"}

# -------------------------------------------------------------
# Static Single-Port Frontend SPA Serving
# -------------------------------------------------------------
dist_dir = Path(__file__).resolve().parent.parent / "frontend" / "dist"

if (dist_dir / "index.html").is_file():
    # Mount hashed assets
    assets_dir = dist_dir / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="static-assets")

    @app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
    async def serve_index():
        return FileResponse(dist_dir / "index.html", headers={"Cache-Control": "no-cache"})

    @app.api_route("/{full_path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    async def serve_spa_or_asset(full_path: str):
        target_file = dist_dir / full_path
        if full_path and target_file.is_file():
            return FileResponse(target_file)
        return FileResponse(dist_dir / "index.html", headers={"Cache-Control": "no-cache"})
else:
    @app.get("/")
    def root():
        return {"status": "SHADOW CAT Cyber Suite Online", "version": "1.2.0"}
