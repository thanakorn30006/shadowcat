"""
SHADOW CAT — CyberChef-Grade Recipe & Transformation Engine
Provides Shannon Entropy, Expanded Encodings (Base58, Base85, Rot47, Zlib/Gzip, Brainfuck),
and multi-step Recipe Execution Pipeline.
"""

import math
import zlib
import gzip
import base64
import urllib.parse
import re
from typing import Dict, List, Any, Tuple

# Base58 Alphabet (Bitcoin Standard)
B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58_decode(s: str) -> bytes:
    num = 0
    for char in s.strip():
        num = num * 58 + B58_ALPHABET.index(char)
    combined = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    n_pad = len(s) - len(s.lstrip('1'))
    return b'\x00' * n_pad + combined

def b58_encode(b: bytes) -> str:
    num = int.from_bytes(b, 'big')
    res = []
    while num > 0:
        num, rem = divmod(num, 58)
        res.append(B58_ALPHABET[rem])
    n_pad = len(b) - len(b.lstrip(b'\x00'))
    return '1' * n_pad + ''.join(reversed(res))

def rot47(s: str) -> str:
    """Rot47 preserves ASCII 33 (!) to 126 (~) with shift of 47."""
    res = []
    for c in s:
        code = ord(c)
        if 33 <= code <= 126:
            res.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            res.append(c)
    return "".join(res)

def atbash_cipher(s: str) -> str:
    res = []
    for c in s:
        if 'a' <= c <= 'z':
            res.append(chr(ord('z') - (ord(c) - ord('a'))))
        elif 'A' <= c <= 'Z':
            res.append(chr(ord('Z') - (ord(c) - ord('A'))))
        else:
            res.append(c)
    return "".join(res)

def run_brainfuck(code: str, input_str: str = "", max_ops: int = 50000) -> str:
    """Safely executes Brainfuck esoteric programming code with op limits."""
    cleaned = [c for c in code if c in "><+-.,[]"]
    memory = [0] * 30000
    ptr = 0
    in_ptr = 0
    out = []
    
    # Bracket matching
    brackets = {}
    stack = []
    for i, c in enumerate(cleaned):
        if c == '[':
            stack.append(i)
        elif c == ']':
            if stack:
                start = stack.pop()
                brackets[start] = i
                brackets[i] = start
    
    pc = 0
    ops = 0
    while pc < len(cleaned) and ops < max_ops:
        ops += 1
        cmd = cleaned[pc]
        if cmd == '>':
            ptr = (ptr + 1) % 30000
        elif cmd == '<':
            ptr = (ptr - 1) % 30000
        elif cmd == '+':
            memory[ptr] = (memory[ptr] + 1) % 256
        elif cmd == '-':
            memory[ptr] = (memory[ptr] - 1) % 256
        elif cmd == '.':
            out.append(chr(memory[ptr]))
        elif cmd == ',':
            if in_ptr < len(input_str):
                memory[ptr] = ord(input_str[in_ptr]) % 256
                in_ptr += 1
            else:
                memory[ptr] = 0
        elif cmd == '[':
            if memory[ptr] == 0:
                pc = brackets.get(pc, pc)
        elif cmd == ']':
            if memory[ptr] != 0:
                pc = brackets.get(pc, pc)
        pc += 1

    return "".join(out)

def calculate_shannon_entropy(data: bytes) -> Dict[str, Any]:
    """Calculates Shannon Entropy (0.0 to 8.0) and infers data characteristics."""
    if not data:
        return {"entropy": 0.0, "assessment": "Empty Data", "confidence": 1.0}

    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    entropy = round(entropy, 4)

    # Assessment inference
    if entropy < 1.5:
        assessment = "Very Low Entropy (Repetitive or sparse null padding)"
    elif 1.5 <= entropy < 3.5:
        assessment = "Low Entropy (Structured code, HTML, JSON, or Assembly)"
    elif 3.5 <= entropy < 5.0:
        assessment = "Medium Entropy (Standard English plaintext or Source code)"
    elif 5.0 <= entropy < 6.5:
        assessment = "Moderate-High Entropy (Base64, Hex encoded, or structured binary)"
    elif 6.5 <= entropy < 7.6:
        assessment = "High Entropy (Compressed stream: Gzip, Zlib, Deflate, PNG IDAT)"
    else:
        assessment = "Maximum Entropy (Strong Encryption: AES, RSA, Random Key, or Packer)"

    return {
        "entropy": entropy,
        "max_entropy": 8.0,
        "percentage": round((entropy / 8.0) * 100, 1),
        "assessment": assessment,
        "byte_length": length,
        "length": length,
        "unique_bytes": len(freq),
        "classification": "Encrypted or High-Density Compressed Stream" if entropy >= 6.8 else ("Moderate Entropy Encoded" if entropy >= 5.0 else "Standard Plaintext / Code"),
        "is_likely_encrypted_or_compressed": entropy >= 6.8
    }

def execute_cyberchef_recipe(initial_input: str, recipe: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Executes a sequential chain of transformations (CyberChef Bake).
    Each step returns { step, op, input_preview, output_preview, success, error }
    """
    current_data = initial_input
    steps_log = []

    for idx, item in enumerate(recipe):
        op = item.get("op", "").lower().replace(" ", "_").replace("-", "_")
        args = item.get("args", {})
        step_entry = {
            "step": idx + 1,
            "operation": op,
            "input_preview": str(current_data)[:80],
            "success": True,
            "output": "",
            "output_preview": "",
            "error": None
        }

        try:
            # 1. Base64
            if op == "from_base64":
                clean = re.sub(r'[^A-Za-z0-9+/=]', '', str(current_data))
                current_data = base64.b64decode(clean).decode("latin-1", errors="replace")
            elif op == "to_base64":
                raw = current_data.encode("latin-1") if isinstance(current_data, str) else current_data
                current_data = base64.b64encode(raw).decode("utf-8")

            # 2. Hex
            elif op == "from_hex":
                clean = re.sub(r'0[xX]|\\x', '', str(current_data).strip())
                clean = re.sub(r'[\s,:]', '', clean)
                if len(clean) % 2 != 0: clean = "0" + clean
                current_data = bytes.fromhex(clean).decode("latin-1", errors="replace")
            elif op == "to_hex":
                raw = current_data.encode("latin-1") if isinstance(current_data, str) else current_data
                current_data = raw.hex()

            # 3. Base58
            elif op == "from_base58":
                current_data = b58_decode(str(current_data)).decode("latin-1", errors="replace")
            elif op == "to_base58":
                raw = current_data.encode("latin-1") if isinstance(current_data, str) else current_data
                current_data = b58_encode(raw)

            # 4. Base85
            elif op == "from_base85":
                clean = str(current_data).strip().encode("latin-1")
                current_data = base64.b85decode(clean).decode("latin-1", errors="replace")
            elif op == "to_base85":
                raw = current_data.encode("latin-1") if isinstance(current_data, str) else current_data
                current_data = base64.b85encode(raw).decode("utf-8")

            # 5. URL Encoding
            elif op == "url_decode":
                current_data = urllib.parse.unquote(str(current_data))
            elif op == "url_encode":
                current_data = urllib.parse.quote(str(current_data))

            # 6. Rotations
            elif op == "rot13":
                import codecs
                current_data = codecs.decode(str(current_data), 'rot_13')
            elif op == "rot47":
                current_data = rot47(str(current_data))
            elif op == "atbash":
                current_data = atbash_cipher(str(current_data))

            # 7. Compression / Inflation
            elif op in ("zlib_inflate", "zlib_decompress"):
                raw = current_data.encode("latin-1") if isinstance(current_data, str) else current_data
                current_data = zlib.decompress(raw).decode("latin-1", errors="replace")
            elif op == "gzip_decompress":
                raw = current_data.encode("latin-1") if isinstance(current_data, str) else current_data
                current_data = gzip.decompress(raw).decode("latin-1", errors="replace")

            # 8. Esoteric / Misc
            elif op == "brainfuck":
                current_data = run_brainfuck(str(current_data), args.get("input", ""))
            elif op == "reverse":
                current_data = str(current_data)[::-1]

            else:
                step_entry["success"] = False
                step_entry["error"] = f"Unknown operation: {op}"

            step_entry["output"] = str(current_data)
            step_entry["output_preview"] = str(current_data)[:80]
        except Exception as e:
            step_entry["success"] = False
            step_entry["error"] = str(e)

        steps_log.append(step_entry)
        if not step_entry["success"]:
            break

    # Look for flags in final output
    FLAG_REGEX = re.compile(r'(?:flag|ctf|picoctf|htb)\{[a-zA-Z0-9_\-\.\!@#\$\%^&*+=]+\}', re.IGNORECASE)
    flags_found = FLAG_REGEX.findall(str(current_data))

    return {
        "output": str(current_data),
        "final_output": str(current_data),
        "output_length": len(str(current_data)),
        "steps": steps_log,
        "flags_found": list(set(flags_found))
    }

def autonomous_magic_unwrap(initial_input: str, max_depth: int = 8) -> Dict[str, Any]:
    """
    Recursively unwrap nested encodings (Base64, Hex, URL, Base85, ROT13)
    until a CTF flag or plain readable text is discovered.
    """
    FLAG_REGEX = re.compile(r'(?:flag|ctf|picoctf|htb)\{[a-zA-Z0-9_\-\.\!@#\$\%^&*+=]+\}', re.IGNORECASE)
    current = str(initial_input or "").strip()
    if not current:
        return {
            "success": False,
            "depth": 0,
            "recipe": [],
            "flag": None,
            "flags_found": [],
            "output": ""
        }
    recipe_taken: List[Dict[str, Any]] = []
    seen = {current}

    initial_flags = list(set(FLAG_REGEX.findall(current)))
    if initial_flags:
        return {
            "success": True,
            "depth": 0,
            "recipe": [],
            "flag": initial_flags[0],
            "flags_found": initial_flags,
            "output": current
        }

    for depth in range(1, max_depth + 1):
        flags = list(set(FLAG_REGEX.findall(current)))
        if flags:
            break

        progressed = False

        # Attempt 1: Hex
        clean_hex = re.sub(r'0[xX]|\\x', '', current.strip())
        clean_hex = re.sub(r'[\s,:]', '', clean_hex)
        if len(clean_hex) >= 4 and len(clean_hex) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in clean_hex):
            try:
                dec = bytes.fromhex(clean_hex).decode("latin-1", errors="replace")
                printable = sum(1 for c in dec if 32 <= ord(c) <= 126 or ord(c) in (10, 13))
                if (printable / max(len(dec), 1) > 0.6 or any(c in dec for c in ["{", "}", "_"])) and dec not in seen:
                    current = dec
                    seen.add(current)
                    recipe_taken.append({"step": depth, "op": "from_hex", "preview": current[:60]})
                    progressed = True
            except Exception:
                pass

        # Attempt 2: Base64
        if not progressed:
            clean_b64 = re.sub(r'[^A-Za-z0-9+/=]', '', current)
            if len(clean_b64) >= 4 and len(clean_b64) % 4 == 0:
                try:
                    raw = base64.b64decode(clean_b64)
                    dec = raw.decode("latin-1", errors="replace")
                    printable = sum(1 for c in dec if 32 <= ord(c) <= 126 or ord(c) in (10, 13))
                    if (printable / max(len(dec), 1) >= 0.82 or any(f in dec for f in ["flag{", "ctf{", "picoCTF{", "htb{"])) and dec not in seen:
                        current = dec
                        seen.add(current)
                        recipe_taken.append({"step": depth, "op": "from_base64", "preview": current[:60]})
                        progressed = True
                except Exception:
                    pass

        # Attempt 3: URL Decode
        if not progressed and "%" in current:
            try:
                dec = urllib.parse.unquote(current)
                if dec != current and dec not in seen:
                    current = dec
                    seen.add(current)
                    recipe_taken.append({"step": depth, "op": "url_decode", "preview": current[:60]})
                    progressed = True
            except Exception:
                pass

        # Attempt 4: ROT13
        if not progressed:
            rot_candidate = ""
            for c in current:
                if 'a' <= c <= 'z':
                    rot_candidate += chr((ord(c) - ord('a') + 13) % 26 + ord('a'))
                elif 'A' <= c <= 'Z':
                    rot_candidate += chr((ord(c) - ord('A') + 13) % 26 + ord('A'))
                else:
                    rot_candidate += c
            rot_flags = list(set(FLAG_REGEX.findall(rot_candidate)))
            clean_rot = rot_candidate.strip()
            looks_b64 = len(clean_rot) >= 12 and len(clean_rot) % 4 == 0 and bool(re.match(r'^[A-Za-z0-9+/]+={0,2}$', clean_rot))
            if rot_flags or (looks_b64 and clean_rot not in seen):
                current = clean_rot
                seen.add(current)
                recipe_taken.append({"step": depth, "op": "rot13", "preview": current[:60]})
                progressed = True
                if rot_flags:
                    break

        if not progressed:
            break

    final_flags = list(set(FLAG_REGEX.findall(current)))

    return {
        "success": len(final_flags) > 0 or len(recipe_taken) > 0,
        "depth": len(recipe_taken),
        "recipe": recipe_taken,
        "flag": final_flags[0] if final_flags else None,
        "flags_found": final_flags,
        "output": current
    }
