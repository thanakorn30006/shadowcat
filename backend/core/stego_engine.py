"""
SHADOW CAT — Digital Forensics: Image Steganography & LSB Carving Engine
Performs LSB bit-plane extraction (RGB, R, G, B), trailing overlay (appended payload) detection,
and flag/magic byte discovery across PNG, JPEG, BMP, and GIF images.
"""

import re
import os
from typing import Dict, List, Any, Optional
from PIL import Image

FLAG_REGEX = re.compile(r'(?:flag|ctf|picoctf|htb)\{[a-zA-Z0-9_\-\.\!@#\$\%^&*+=]+\}', re.IGNORECASE)

KNOWN_MAGICS = {
    b"PK\x03\x04": "Zip Archive / Embedded Office Document",
    b"\x89PNG": "Embedded PNG Image",
    b"GIF89a": "Embedded GIF Animation",
    b"GIF87a": "Embedded GIF Image",
    b"\xff\xd8\xff": "Embedded JPEG Image",
    b"\x7fELF": "Embedded Linux ELF Executable",
    b"MZ": "Embedded Windows PE / DOS Executable",
    b"7z\xbc\xaf\x27\x1c": "Embedded 7-Zip Archive",
    b"BZh": "Embedded Bzip2 Compressed Stream"
}

def analyze_image_steganography(filepath: str, max_extract_bytes: int = 16384) -> Dict[str, Any]:
    """
    Performs comprehensive steganography analysis on the provided image file.
    Returns:
    {
        "is_image": bool,
        "format": str,
        "dimensions": str,
        "trailing_overlay": { "detected": bool, "size_bytes": int, "preview_hex": str, "flags_found": List[str] },
        "lsb_analysis": {
            "rgb_combined": { "flags": List[str], "sample_text": str, "embedded_magics": List[str] },
            "red_channel": { "flags": List[str], "sample_text": str },
            "green_channel": { "flags": List[str], "sample_text": str },
            "blue_channel": { "flags": List[str], "sample_text": str }
        },
        "exif_metadata": Dict[str, str],
        "flags_found": List[str]
    }
    """
    if not os.path.exists(filepath):
        return {"is_image": False, "error": f"File not found: {filepath}"}

    with open(filepath, "rb") as f:
        file_bytes = f.read()

    # 1. Trailing Overlay Check (Appended data after file terminator)
    trailing_info = {"detected": False, "size_bytes": 0, "preview": "", "flags_found": []}
    
    # PNG check: IEND chunk (b'IEND\xaeB`\x82')
    iend_pos = file_bytes.find(b'IEND\xaeB`\x82')
    if iend_pos != -1:
        iend_end = iend_pos + 8
        if iend_end < len(file_bytes):
            overlay_data = file_bytes[iend_end:]
            trailing_info["detected"] = True
            trailing_info["size_bytes"] = len(overlay_data)
            trailing_info["preview"] = overlay_data[:120].decode("latin-1", errors="replace")
            trailing_info["flags_found"] = list(set(FLAG_REGEX.findall(overlay_data.decode("latin-1", errors="ignore"))))

    # JPEG check: EOI marker (b'\xff\xd9')
    if not trailing_info["detected"] and file_bytes.startswith(b'\xff\xd8'):
        eoi_pos = file_bytes.rfind(b'\xff\xd9')
        if eoi_pos != -1 and (eoi_pos + 2) < len(file_bytes):
            overlay_data = file_bytes[eoi_pos + 2:]
            trailing_info["detected"] = True
            trailing_info["size_bytes"] = len(overlay_data)
            trailing_info["preview"] = overlay_data[:120].decode("latin-1", errors="replace")
            trailing_info["flags_found"] = list(set(FLAG_REGEX.findall(overlay_data.decode("latin-1", errors="ignore"))))

    # 2. PIL Image Pixel Loading & LSB Analysis
    import itertools
    try:
        with Image.open(filepath) as img:
            img_format = img.format or "UNKNOWN"
            dimensions = f"{img.width}x{img.height}"
            
            # 3. EXIF & Metadata Extraction
            exif_meta = {}
            try:
                info = img._getexif() if hasattr(img, '_getexif') and callable(img._getexif) else None
                if info:
                    for k, v in info.items():
                        if isinstance(v, (str, int, float)):
                            exif_meta[str(k)] = str(v)
            except Exception:
                pass

            rgb_img = img.convert("RGB")
            # Stream only up to 200,000 pixels without buffering massive images into RAM
            sample_pixels = list(itertools.islice(rgb_img.getdata(), 200000))
    except Exception:
        # Not a valid image or corrupted
        return {
            "is_image": False,
            "trailing_overlay": trailing_info,
            "flags_found": trailing_info["flags_found"]
        }

    # 4. LSB Bit Planes
    all_flags = list(trailing_info["flags_found"])

    def bits_to_bytes(bit_list: List[int]) -> bytes:
        out = bytearray()
        for i in range(0, len(bit_list) - 7, 8):
            byte = 0
            for b_idx in range(8):
                byte = (byte << 1) | bit_list[i + b_idx]
            out.append(byte)
        return bytes(out)

    lsb_results = {}
    try:
        r_bits = []
        g_bits = []
        b_bits = []
        rgb_bits = []

        for r, g, b in sample_pixels:
            rb, gb, bb = r & 1, g & 1, b & 1
            r_bits.append(rb)
            g_bits.append(gb)
            b_bits.append(bb)
            rgb_bits.extend([rb, gb, bb])

        # Channel 1: Combined RGB
        rgb_bytes = bits_to_bytes(rgb_bits)[:max_extract_bytes]
        rgb_text = rgb_bytes.decode("latin-1", errors="replace")
        rgb_flags = list(set(FLAG_REGEX.findall(rgb_text)))
        all_flags.extend(rgb_flags)

        # Check for magic signatures in RGB LSB
        rgb_magics = []
        for magic, name in KNOWN_MAGICS.items():
            if magic in rgb_bytes:
                rgb_magics.append(name)

        # Extract printable ASCII sequences
        def get_printable_sample(b: bytes) -> str:
            chars = []
            for byte in b[:500]:
                if 32 <= byte <= 126 or byte in (10, 13):
                    chars.append(chr(byte))
                else:
                    chars.append('.')
            return "".join(chars).strip()

        lsb_results["rgb_combined"] = {
            "flags": rgb_flags,
            "sample_text": get_printable_sample(rgb_bytes),
            "embedded_magics": rgb_magics,
            "extracted_length": len(rgb_bytes)
        }

        # Individual Channels (Red, Green, Blue)
        for ch_name, ch_bits in [("red_channel", r_bits), ("green_channel", g_bits), ("blue_channel", b_bits)]:
            ch_bytes = bits_to_bytes(ch_bits)[:max_extract_bytes]
            ch_text = ch_bytes.decode("latin-1", errors="replace")
            ch_flags = list(set(FLAG_REGEX.findall(ch_text)))
            all_flags.extend(ch_flags)
            lsb_results[ch_name] = {
                "flags": ch_flags,
                "sample_text": get_printable_sample(ch_bytes)
            }

    except Exception as e:
        lsb_results["error"] = str(e)

    unique_flags = sorted(list(set(all_flags)))

    return {
        "is_image": True,
        "format": img_format,
        "dimensions": dimensions,
        "trailing_overlay": trailing_info,
        "lsb_analysis": lsb_results,
        "exif_metadata": exif_meta,
        "flags_found": unique_flags
    }
