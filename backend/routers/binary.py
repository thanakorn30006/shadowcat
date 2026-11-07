import sys, os, struct, re
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.config import UPLOAD_DIR

router = APIRouter()

DANGEROUS_FUNCTIONS = {
    "gets": "Extreme risk: unbounded buffer overflow (gets has no buffer limits)",
    "strcpy": "High risk: unbounded string copy without size checking",
    "strcat": "High risk: unbounded string concatenation",
    "sprintf": "High risk: string formatting without bounds checking",
    "vsprintf": "High risk: variable arguments formatting without bounds",
    "system": "Exploitable: command execution vector (ret2libc / ROP target)",
    "execve": "Exploitable: syscall to spawn shell or execute arbitrary binary",
    "popen": "Exploitable: process execution pipeline",
    "printf": "Format string risk if user input passed directly without format specifier",
    "scanf": "Buffer overflow risk if %s used without width limit",
    "ptrace": "Anti-debugging technique detector",
    "memcmp": "Potential flag verification comparison target",
    "strcmp": "Potential flag verification comparison target",
    "strncmp": "Potential flag verification comparison target",
}

def analyze_elf_binary(filepath: str, data: bytes) -> dict:
    """Analyze Linux ELF binary for architecture, checksec mitigations, and dangerous functions."""
    result = {
        "format": "ELF (Executable and Linkable Format)",
        "bits": 64 if data[4] == 2 else 32,
        "endian": "Little Endian" if data[5] == 1 else "Big Endian",
        "os_abi": "System V" if data[7] == 0 else "Linux" if data[7] == 3 else f"ABI {data[7]}",
        "type": "Executable" if data[16] == 2 else "Shared Object / PIE" if data[16] == 3 else "Relocatable",
        "checksec": {
            "nx": "Unknown",
            "canary": "Unknown",
            "pie": "Unknown",
            "relro": "Unknown",
        },
        "dangerous_imports": [],
        "interesting_strings": [],
    }

    # PIE check
    if data[16] == 3:
        result["checksec"]["pie"] = "PIE enabled (Shared Object/DYN)"
    elif data[16] == 2:
        result["checksec"]["pie"] = "No PIE (Executable/EXEC - Fixed Addresses)"

    # Architecture
    machine_id = struct.unpack("<H" if data[5] == 1 else ">H", data[18:20])[0]
    arch_map = {0x03: "x86 (32-bit)", 0x3E: "x86_64 (AMD64)", 0x28: "ARM (32-bit)", 0xB7: "AArch64 (ARM64)", 0x08: "MIPS"}
    result["architecture"] = arch_map.get(machine_id, f"Machine ID: 0x{machine_id:02x}")

    # Inspect program headers for GNU_STACK (NX flag)
    try:
        is_64 = (data[4] == 2)
        endian = "<" if data[5] == 1 else ">"
        phoff = struct.unpack(f"{endian}{'Q' if is_64 else 'I'}", data[32:40] if is_64 else data[28:32])[0]
        phentsize = struct.unpack(f"{endian}H", data[54:56] if is_64 else data[42:44])[0]
        phnum = struct.unpack(f"{endian}H", data[56:58] if is_64 else data[44:46])[0]

        nx_found = False
        for i in range(phnum):
            offset = phoff + i * phentsize
            if offset + phentsize <= len(data):
                p_type = struct.unpack(f"{endian}I", data[offset:offset+4])[0]
                if p_type == 0x6474e551:  # PT_GNU_STACK
                    p_flags = struct.unpack(f"{endian}I", data[offset+4:offset+8])[0] if is_64 else struct.unpack(f"{endian}I", data[offset+24:offset+28])[0]
                    # PF_X is 0x1
                    if (p_flags & 1) == 0:
                        result["checksec"]["nx"] = "NX Enabled (Stack not executable)"
                    else:
                        result["checksec"]["nx"] = "NX Disabled (Stack EXECUTABLE - Shellcode ready!)"
                    nx_found = True
                    break
        if not nx_found:
            result["checksec"]["nx"] = "No PT_GNU_STACK found (Likely executable stack)"
    except Exception:
        pass

    # Scan for symbols / imports
    symbols = set(re.findall(rb'[A-Za-z0-9_]{3,40}', data))
    symbols_str = [s.decode('latin-1') for s in symbols]
    
    # Canary check
    if "__stack_chk_fail" in symbols_str or "__stack_chk_guard" in symbols_str:
        result["checksec"]["canary"] = "Stack Canary Found (__stack_chk_fail present)"
    else:
        result["checksec"]["canary"] = "No Stack Canary Found (Buffer overflow feasible!)"

    # Dangerous functions
    for func, desc in DANGEROUS_FUNCTIONS.items():
        if func in symbols_str:
            result["dangerous_imports"].append({"function": func, "risk": desc})

    # Strings
    from core.ctf_agent import search_flags
    raw_text = data.decode('latin-1', errors='ignore')
    flags = search_flags(raw_text)
    result["flags_found"] = flags

    return result

def analyze_pe_binary(data: bytes) -> dict:
    """Analyze Windows PE (Portable Executable) binary."""
    result = {
        "format": "PE (Windows Executable / DLL)",
        "bits": 32,
        "checksec": {
            "dep": "Unknown",
            "aslr": "Unknown",
            "cfg": "Unknown",
        },
        "dangerous_imports": [],
        "flags_found": []
    }
    symbols = set(re.findall(rb'[A-Za-z0-9_]{3,40}', data))
    symbols_str = [s.decode('latin-1') for s in symbols]

    for func, desc in DANGEROUS_FUNCTIONS.items():
        if func in symbols_str:
            result["dangerous_imports"].append({"function": func, "risk": desc})

    from core.ctf_agent import search_flags
    raw_text = data.decode('latin-1', errors='ignore')
    result["flags_found"] = search_flags(raw_text)
    return result

@router.post("/inspect")
async def inspect_binary(file: UploadFile = File(...)):
    """Upload an ELF or PE binary for Checksec mitigations, dangerous calls & disassembly preview."""
    MAX_FILE_SIZE = 104857600  # 100 MB Limit
    try:
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"Binary file exceeds 100MB limit ({len(content) / 1024 / 1024:.1f}MB)."
            )

        import uuid
        clean_name = re.sub(r'[^A-Za-z0-9_.\-]', '_', file.filename or 'binary.bin')
        dest = UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{clean_name}"
        with open(dest, "wb") as f:
            f.write(content)

        if content.startswith(b'\x7fELF'):
            analysis = analyze_elf_binary(clean_name, content)
        elif content.startswith(b'MZ'):
            analysis = analyze_pe_binary(content)
        elif content.startswith(b'\xcf\xfa\xed\xfe') or content.startswith(b'\xca\xfe\xba\xbe'): # Mach-O
            analysis = {"format": "Mach-O Executable", "checksec": {"nx": "Enabled", "pie": "PIE enabled", "canary": "Detected", "relro": "N/A"}, "dangerous_imports": [], "flags_found": []}
        else:
            raise HTTPException(status_code=400, detail="File is neither an ELF, PE, nor Mach-O executable binary")

        # Run Disassembly Engine
        from core.disasm_engine import disassemble_binary
        disasm = disassemble_binary(str(dest))
        analysis["disassembly"] = disasm

        analysis["filename"] = clean_name
        analysis["size_bytes"] = len(content)
        return JSONResponse(content=analysis)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------------------------------------
# De Bruijn Cyclic Pattern & Offset Finder (Pwntools Replacement)
# -------------------------------------------------------------
import string
from pydantic import BaseModel
from typing import Optional

class CyclicGenerateRequest(BaseModel):
    length: Optional[int] = 200
    width: Optional[int] = 4

class CyclicFindRequest(BaseModel):
    pattern: str
    width: Optional[int] = 4
    max_length: Optional[int] = 10000

def de_bruijn_cyclic(length: int = 200, width: int = 4) -> str:
    alphabet = string.ascii_lowercase
    n = width
    k = len(alphabet)
    a = [0] * (k * n)
    sequence = []
    stop = False

    def db(t, p):
        nonlocal stop
        if stop:
            return
        if t > n:
            if n % p == 0:
                sequence.extend(a[1 : p + 1])
                if len(sequence) >= length:
                    stop = True
                    return
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                if stop:
                    return
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    res = "".join(alphabet[i] for i in sequence)
    while len(res) < length:
        res += res
    return res[:length]

def find_offset_in_cyclic(query: str, width: int = 4, max_len: int = 10000) -> Optional[int]:
    q = query.strip()
    if not q:
        return None

    le_str = be_str = q
    if q.startswith("0x") or q.startswith("0X"):
        try:
            hex_val = q[2:]
            if len(hex_val) % 2 != 0:
                hex_val = "0" + hex_val
            raw_bytes = bytes.fromhex(hex_val)
            le_str = raw_bytes[::-1].decode("latin-1", errors="ignore")
            be_str = raw_bytes.decode("latin-1", errors="ignore")
        except Exception:
            pass

    haystack = de_bruijn_cyclic(max_len, width)
    for candidate in [le_str, be_str, q]:
        if candidate and candidate in haystack:
            return haystack.index(candidate)
    return None

@router.post("/cyclic-generate")
def cyclic_generate_endpoint(req: CyclicGenerateRequest):
    """Generate De Bruijn cyclic sequence for buffer overflow offset determination."""
    length = max(4, min(req.length or 200, 20000))
    width = max(2, min(req.width or 4, 8))
    pattern = de_bruijn_cyclic(length, width)
    return {
        "pattern": pattern,
        "length": len(pattern),
        "width": width
    }

@router.post("/cyclic-find")
def cyclic_find_endpoint(req: CyclicFindRequest):
    """Find exact offset of crash value (hex or ASCII) in De Bruijn cyclic sequence."""
    width = max(2, min(req.width or 4, 8))
    max_len = max(100, min(req.max_length or 10000, 50000))
    offset = find_offset_in_cyclic(req.pattern, width, max_len)
    return {
        "query": req.pattern,
        "found": offset is not None,
        "offset": offset,
        "width": width,
        "suggestion": f"EIP/RIP Control at offset {offset}. Payload padding: 'A' * {offset}" if offset is not None else "Pattern not found in cyclic sequence"
    }
