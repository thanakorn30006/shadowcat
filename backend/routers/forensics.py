import sys, shutil, os, hashlib, re, zipfile, tempfile
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from starlette.background import BackgroundTask

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.config import UPLOAD_DIR
from core.voice import announce_flag

router = APIRouter()

def generate_hexdump(data: bytes, max_bytes: int = 1024) -> str:
    lines = []
    chunk = data[:max_bytes]
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        hex_bytes = " ".join(f"{b:02x}" for b in row)
        ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        lines.append(f"{i:08x}  {hex_bytes:<48}  |{ascii_repr}|")
    return "\n".join(lines)

@router.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """Upload a file and run full CTF forensics analysis."""
    MAX_FILE_SIZE = 104857600  # 100 MB Safeguard
    try:
        from core.ctf_agent import analyze_file as _analyze, extract_strings
        from core.pcap_analyzer import deep_analyze_pcap
        
        # Clean filename to prevent injection / path traversal and collision
        import uuid
        clean_name = re.sub(r'[^A-Za-z0-9_.\-]', '_', file.filename or 'upload.bin')
        dest = UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{clean_name}"
        
        # Read content with size check to prevent OOM
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds maximum allowed size of 100MB ({len(content) / 1024 / 1024:.1f}MB detected). Please carve smaller packet slices."
            )

        with open(dest, "wb") as f:
            f.write(content)
            
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        hexdump_preview = generate_hexdump(content, max_bytes=1024)
        
        # Run deep forensic pipeline
        result = _analyze(str(dest))

        # If file is PCAP / PCAPNG, attach deep Wireshark-level dissection
        if clean_name.lower().endswith(('.pcap', '.pcapng', '.cap')):
            pcap_deep = deep_analyze_pcap(str(dest))
            result["pcap_dissection"] = pcap_deep
            if pcap_deep.get("flags_found"):
                result["flags_found"] = list(set(result.get("flags_found", []) + pcap_deep["flags_found"]))

        # If file is an image, attach deep steganography & LSB analysis
        if clean_name.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp')):
            from core.stego_engine import analyze_image_steganography
            stego_res = analyze_image_steganography(str(dest))
            result["stego_analysis"] = stego_res
            if stego_res.get("flags_found"):
                result["flags_found"] = list(set(result.get("flags_found", []) + stego_res["flags_found"]))
        
        # Announce via voice if flag found
        if result.get("flags_found"):
            announce_flag(result["flags_found"][0])
            
        # Extract strings for search/filter table
        str_res = extract_strings(str(dest), min_len=4)
        interesting_strings = str_res.get("interesting_strings", [])[:300]
        
        # Enrich result
        result["file_meta"] = {
            "filename": clean_name,
            "size_bytes": len(content),
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash,
            "hexdump": hexdump_preview,
            "strings_count": str_res.get("total_strings", 0),
            "sample_strings": interesting_strings
        }
        
        # Check if any extracted/carved files exist
        extracted_dir = UPLOAD_DIR / "extracted"
        extracted_count = len([f for f in extracted_dir.rglob("*") if f.is_file()]) if extracted_dir.exists() else 0
        result["extracted_artifacts_count"] = extracted_count
        
        return JSONResponse(content=result)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download-extracted")
async def download_extracted_artifacts():
    """Package all carved and extracted artifacts from UPLOAD_DIR/extracted into a downloadable zip file."""
    try:
        extracted_dir = UPLOAD_DIR / "extracted"
        if not extracted_dir.exists():
            raise HTTPException(status_code=404, detail="No extracted artifacts directory found.")
            
        files = [p for p in extracted_dir.rglob("*") if p.is_file()]
        if not files:
            raise HTTPException(status_code=404, detail="No carved artifacts currently available in extracted directory.")
            
        # Create temp zip file
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        with zipfile.ZipFile(temp_zip.name, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in files:
                arcname = file_path.relative_to(extracted_dir)
                zf.write(file_path, arcname=str(arcname))
                
        return FileResponse(
            path=temp_zip.name,
            filename="shadowsolve_carved_artifacts.zip",
            media_type="application/zip",
            background=BackgroundTask(lambda: os.unlink(temp_zip.name) if os.path.exists(temp_zip.name) else None)
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------------------------------------
# Magic Byte Repair & Header Restoration Engine
# -------------------------------------------------------------
from fastapi import Form

MAGIC_SIGNATURES = {
    "png": {"magic": b"\x89PNG\r\n\x1a\n", "name": "PNG Image", "ext": ".png", "media_type": "image/png"},
    "jpg": {"magic": b"\xff\xd8\xff\xe0", "name": "JPEG Image", "ext": ".jpg", "media_type": "image/jpeg"},
    "gif": {"magic": b"GIF89a", "name": "GIF89a Image", "ext": ".gif", "media_type": "image/gif"},
    "zip": {"magic": b"PK\x03\x04", "name": "ZIP Archive", "ext": ".zip", "media_type": "application/zip"},
    "pdf": {"magic": b"%PDF-", "name": "PDF Document", "ext": ".pdf", "media_type": "application/pdf"},
    "elf": {"magic": b"\x7fELF", "name": "Linux ELF Executable", "ext": ".elf", "media_type": "application/octet-stream"},
    "pcap": {"magic": b"\xd4\xc3\xb2\xa1", "name": "PCAP Capture (Little Endian)", "ext": ".pcap", "media_type": "application/vnd.tcpdump.pcap"},
    "pcapng": {"magic": b"\n\r\r\n", "name": "PCAPNG Capture", "ext": ".pcapng", "media_type": "application/octet-stream"},
}

@router.post("/check-header")
async def check_header(file: UploadFile = File(...)):
    """Inspects file prefix for corrupted or missing magic byte signatures."""
    content = await file.read(64)
    filename = file.filename or "unknown"
    ext = Path(filename).suffix.lower().lstrip(".")
    
    expected = MAGIC_SIGNATURES.get(ext)
    corrupted = False
    details = ""
    
    if expected:
        exp_magic = expected["magic"]
        if not content.startswith(exp_magic):
            corrupted = True
            details = f"File extension is '.{ext}', but header starts with '{content[:len(exp_magic)].hex()}' instead of expected '{exp_magic.hex()}'."
    
    return {
        "filename": filename,
        "extension": ext,
        "current_header_hex": content[:16].hex(),
        "is_corrupted": corrupted,
        "expected_format": expected["name"] if expected else "Unknown Format",
        "expected_magic_hex": expected["magic"].hex() if expected else None,
        "diagnosis": details or "Header matches extension or format unknown"
    }

@router.post("/repair-header")
async def repair_header(
    file: UploadFile = File(...),
    target_format: str = Form(...)
):
    """Overwrites corrupted file header with authentic magic signature and streams repaired file."""
    fmt = target_format.lower().strip()
    spec = MAGIC_SIGNATURES.get(fmt)
    if not spec:
        raise HTTPException(status_code=400, detail=f"Unsupported target format: '{target_format}'. Supported: {list(MAGIC_SIGNATURES.keys())}")
    
    MAX_FILE_SIZE = 104857600  # 100 MB Safeguard
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds 100MB limit ({len(content) / 1024 / 1024:.1f}MB)."
        )

    magic = spec["magic"]
    
    repaired_content = magic + content[len(magic):]
    
    base_name = Path(file.filename or "repaired_file").stem
    out_filename = f"{base_name}_repaired{spec['ext']}"
    
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=spec['ext'])
    try:
        temp_file.write(repaired_content)
        temp_file.flush()
    finally:
        temp_file.close()
        
    return FileResponse(
        path=temp_file.name,
        filename=out_filename,
        media_type=spec["media_type"],
        background=BackgroundTask(lambda: os.unlink(temp_file.name) if os.path.exists(temp_file.name) else None)
    )
