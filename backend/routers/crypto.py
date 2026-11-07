import sys, string, struct, re
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.voice import announce_flag

router = APIRouter()

class CryptoRequest(BaseModel):
    text: str
    context: Optional[str] = ""

class CaesarAllRequest(BaseModel):
    text: str

class VigenereRequest(BaseModel):
    text: str
    key: str
    decrypt: bool = True

class XORBruteforceRequest(BaseModel):
    text: str
    is_hex: Optional[bool] = False

class EndianRequest(BaseModel):
    value: str

@router.post("/decode")
def decode_text(req: CryptoRequest):
    """Auto-detect encoding and decode. Supports 20+ encodings + cipher attacks."""
    try:
        from core.ctf_agent import ctf_analyze_text
        from core.config import GEMINI_API_KEY
        result = ctf_analyze_text(req.text, req.context or "", GEMINI_API_KEY)
        if result.get("flags_found"):
            announce_flag(result["flags_found"][0])
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/caesar-all")
def caesar_all(req: CaesarAllRequest):
    """Generate all 25 Caesar cipher shifts simultaneously."""
    from core.ctf_agent import caesar_decode, search_flags
    shifts = []
    found_flags = []
    for shift in range(1, 26):
        decoded = caesar_decode(req.text, shift)
        flags = search_flags(decoded)
        if flags:
            found_flags.extend(flags)
        shifts.append({
            "shift": shift,
            "text": decoded,
            "has_flag": len(flags) > 0,
            "flags": flags
        })
    if found_flags:
        announce_flag(found_flags[0])
    return {"shifts": shifts}

@router.post("/vigenere")
def vigenere_tool(req: VigenereRequest):
    """Encrypt or Decrypt with Vigenere given a specific key."""
    from core.ctf_agent import search_flags
    key = req.key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="Key cannot be empty")
        
    result = []
    key_idx = 0
    k_len = len(key)
    
    for c in req.text:
        if c.isalpha():
            k_char = key[key_idx % k_len].upper()
            k_shift = ord(k_char) - ord('A')
            if req.decrypt:
                k_shift = -k_shift
                
            base = ord('A') if c.isupper() else ord('a')
            shifted = chr((ord(c) - base + k_shift) % 26 + base)
            result.append(shifted)
            key_idx += 1
        else:
            result.append(c)
            
    output = "".join(result)
    flags = search_flags(output)
    if flags:
        announce_flag(flags[0])
    return {"result": output, "flags": flags}

@router.post("/xor-bruteforce")
def xor_bruteforce(req: XORBruteforceRequest):
    """Brute force all 256 single-byte XOR keys and rank candidates by English & Flag likelihood via threadpool."""
    from core.ctf_agent import search_flags
    raw_input = req.text.strip()
    if not raw_input:
        raise HTTPException(status_code=400, detail="Ciphertext cannot be empty")
        
    # Check if input is hex
    is_hex = req.is_hex
    clean_hex = re.sub(r'[^0-9a-fA-F]', '', raw_input)
    if not is_hex and len(clean_hex) >= 4 and len(clean_hex) % 2 == 0 and len(clean_hex) == len(raw_input.replace(' ', '')):
        is_hex = True

    try:
        if is_hex:
            data_bytes = bytes.fromhex(clean_hex)
        else:
            data_bytes = raw_input.encode('utf-8', errors='ignore')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse input as bytes: {str(e)}")

    if not data_bytes:
        raise HTTPException(status_code=400, detail="No valid bytes parsed from input")

    candidates = []
    freq_letters = set(b"etaoinshrdluETAOINSHRDLU ")

    for key in range(256):
        dec = bytes([b ^ key for b in data_bytes])
        
        # Calculate readability score
        printable_count = sum(1 for b in dec if 32 <= b <= 126 or b in (9, 10, 13))
        freq_count = sum(1 for b in dec if b in freq_letters)
        ratio = printable_count / len(dec)
        score = (printable_count * 2) + (freq_count * 3)
        
        # Decode as ASCII / UTF-8 safely
        decoded_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in dec)
        
        # Flag search
        flags = search_flags(decoded_str)
        if flags:
            score += 500
            
        # Only retain candidates with reasonable printable ratio or flags
        if ratio > 0.65 or flags:
            key_repr = f"0x{key:02x} ({key})"
            if 32 <= key <= 126:
                key_repr += f" '{chr(key)}'"
                
            candidates.append({
                "key": key,
                "key_repr": key_repr,
                "text": decoded_str,
                "has_flag": len(flags) > 0,
                "flags": flags,
                "printable_ratio": round(ratio * 100, 1),
                "score": score
            })

    # Sort candidates by score descending
    candidates.sort(key=lambda x: x["score"], reverse=True)
    return {
        "total_keys_tested": 256,
        "viable_candidates_count": len(candidates),
        "candidates": candidates[:30] # Return top 30
    }

@router.post("/endianness")
def endianness_converter(req: EndianRequest):
    """Convert address or integer between Little Endian, Big Endian, hex, and pwntools p32/p64 format via threadpool."""
    val_str = req.value.strip()
    if not val_str:
        raise HTTPException(status_code=400, detail="Value cannot be empty")
        
    try:
        # Check if hex format (e.g. 0x08048492 or \x92\x84\x04\x08)
        if r'\x' in val_str:
            # Escaped raw bytes input e.g. \x92\x84\x04\x08
            raw_hex = "".join(x for x in val_str.split(r'\x') if x)
            parsed_bytes = bytes.fromhex(raw_hex)
            if len(parsed_bytes) == 4:
                num = struct.unpack("<I", parsed_bytes)[0]
            elif len(parsed_bytes) == 8:
                num = struct.unpack("<Q", parsed_bytes)[0]
            else:
                num = int.from_bytes(parsed_bytes, 'little')
        elif val_str.startswith("0x") or val_str.startswith("0X"):
            num = int(val_str, 16)
        elif val_str.isdigit():
            num = int(val_str, 10)
        else:
            # Try raw hex
            num = int(val_str, 16)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Cannot parse number/hex address: {str(e)}")

    # 32-bit representations
    p32_num = num & 0xFFFFFFFF
    try:
        p32_le_bytes = struct.pack("<I", p32_num)
        p32_be_bytes = struct.pack(">I", p32_num)
        p32_le_esc = "".join(f"\\x{b:02x}" for b in p32_le_bytes)
        p32_be_esc = "".join(f"\\x{b:02x}" for b in p32_be_bytes)
        p32_le_hex = p32_le_bytes.hex()
        p32_be_hex = p32_be_bytes.hex()
    except Exception:
        p32_le_esc = p32_be_esc = p32_le_hex = p32_be_hex = "Overflow"

    # 64-bit representations
    p64_num = num & 0xFFFFFFFFFFFFFFFF
    try:
        p64_le_bytes = struct.pack("<Q", p64_num)
        p64_be_bytes = struct.pack(">Q", p64_num)
        p64_le_esc = "".join(f"\\x{b:02x}" for b in p64_le_bytes)
        p64_be_esc = "".join(f"\\x{b:02x}" for b in p64_be_bytes)
        p64_le_hex = p64_le_bytes.hex()
        p64_be_hex = p64_be_bytes.hex()
    except Exception:
        p64_le_esc = p64_be_esc = p64_le_hex = p64_be_hex = "Overflow"

    return {
        "input": val_str,
        "integer_val": num,
        "hex_val": f"0x{num:x}",
        "32bit": {
            "little_endian_bytes": p32_le_esc,
            "little_endian_hex": p32_le_hex,
            "big_endian_bytes": p32_be_esc,
            "big_endian_hex": p32_be_hex,
            "pwntools": f"p32(0x{p32_num:x})",
            "pwntools_hex": f"p32(0x{p32_num:x}).hex()"
        },
        "64bit": {
            "little_endian_bytes": p64_le_esc,
            "little_endian_hex": p64_le_hex,
            "big_endian_bytes": p64_be_esc,
            "big_endian_hex": p64_be_hex,
            "pwntools": f"p64(0x{p64_num:x})",
            "pwntools_hex": f"p64(0x{p64_num:x}).hex()"
        }
    }

# -------------------------------------------------------------
# CyberChef-Grade Entropy & Recipe Chaining Pipeline
# -------------------------------------------------------------
class EntropyRequest(BaseModel):
    text: str
    is_hex: Optional[bool] = False

class RecipeRequest(BaseModel):
    input: str
    recipe: List[dict]

class MagicUnwrapRequest(BaseModel):
    input: str
    max_depth: Optional[int] = 8

@router.post("/entropy")
def get_entropy(req: EntropyRequest):
    """Calculates Shannon Entropy and infers encryption vs compression vs plaintext."""
    from core.cyberchef_engine import calculate_shannon_entropy
    raw_data = bytes.fromhex(req.text.replace(" ", "")) if req.is_hex else req.text.encode("latin-1")
    return calculate_shannon_entropy(raw_data)

@router.post("/recipe")
def run_recipe(req: RecipeRequest):
    """Executes a sequential chain of transformations (CyberChef Bake pipeline)."""
    from core.cyberchef_engine import execute_cyberchef_recipe
    return execute_cyberchef_recipe(req.input, req.recipe)

@router.post("/magic-unwrap")
def magic_unwrap(req: MagicUnwrapRequest):
    """Recursively unwraps multi-layered encodings (Hex, Base64, URL, ROT13) until flags or plain text emerge."""
    from core.cyberchef_engine import autonomous_magic_unwrap
    result = autonomous_magic_unwrap(req.input, req.max_depth or 8)
    if result.get("flag"):
        announce_flag(result["flag"])
    return result
