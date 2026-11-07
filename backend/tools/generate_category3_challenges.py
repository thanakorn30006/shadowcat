#!/usr/bin/env python3
"""
Generates Category 3 Challenge Test Files for ShadowSolve Web UI testing.
Targets:
1. challenge_1_ret2libc_vuln.bin    -> Test Binary & Pwn Checksec, Dangerous Imports, Disassembly
2. challenge_2_crash_telemetry.txt  -> Test De Bruijn Cyclic EIP/RIP Offset Finder
3. challenge_3_cyberchef_bake.txt   -> Test CyberChef Sequential Recipe Decoder
4. challenge_4_classify_cases.txt   -> Test CTF Challenge ML Classifier & Auto-Categorization
"""

import os
import struct
import base64
import codecs
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent.parent / "test_challenges_category3"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# 1. Crafted Vulnerable ELF Binary (Pwn / Checksec / Disassembly)
def make_vuln_pwn_binary():
    elf_path = OUT_DIR / "challenge_1_ret2libc_vuln.bin"
    
    # 64-bit ELF Header
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    elf_hdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        2,        # ET_EXEC (Fixed addresses / No PIE)
        0x3E,     # x86_64
        1,        # version
        0x401142, # Entry address
        64,       # Program header offset
        0,        # Section header offset
        0,        # flags
        64, 56, 1, 64, 0, 0
    )
    
    # Program Header: PT_LOAD, Executable + Readable
    prog_hdr = struct.pack(
        "<IIQQQQQQ",
        1, 5, 0, 0x400000, 0x400000, 1024, 1024, 0x1000
    )
    
    # Disassembly code payload mimicking vuln() and main()
    # asm: push rbp; mov rbp, rsp; sub rsp, 0x40; lea rax, [rbp-0x40]; mov rdi, rax; call gets; ...
    code = b"\x55\x48\x89\xe5\x48\x83\xec\x40" # prologue
    code += b"\x48\x8d\x45\xc0\x48\x89\xc7"    # lea rdi, [rbp-0x40]
    code += b"\xe8\x20\x00\x00\x00"            # call gets
    code += b"\x48\x8d\x3d\x30\x00\x00\x00"    # lea rdi, [str_bin_sh]
    code += b"\xe8\x30\x00\x00\x00"            # call system
    code += b"\xb8\x00\x00\x00\x00\xc9\xc3"    # mov eax, 0; leave; ret
    
    # Symbol names and flag payload
    symbols = b"\x00" * 16
    symbols += b"main\x00vuln\x00gets\x00system\x00strcpy\x00puts\x00printf\x00"
    symbols += b"/bin/sh\x00"
    symbols += b"\nFLAG: flag{checksec_ret2libc_rop_gadget_win_8834}\n"
    
    padding = b"\x90" * (1024 - len(elf_hdr) - len(prog_hdr) - len(code) - len(symbols))
    binary_content = elf_hdr + prog_hdr + code + symbols + padding
    
    with open(elf_path, "wb") as f:
        f.write(binary_content)
    print(f"[+] Created: {elf_path.name}")

# 2. Crash Telemetry File for De Bruijn Offset Finder
def make_crash_telemetry():
    txt_path = OUT_DIR / "challenge_2_crash_telemetry.txt"
    # Crash offset at 72 is 'saaa' or 0x61616173 in standard 4-byte De Bruijn
    content = """=== PWN CRASH LOG / GDB EXPLOIT TELEMETRY ===
Target: ./vuln_service
Signal: SIGSEGV (Segmentation Fault - Invalid Memory Address)

Registers State at Crash:
RAX: 0x0000000000000000
RBX: 0x0000000000000000
RCX: 0x00007ffff7eccd80
RDX: 0x0000000000000000
RBP: 0x6161617261616171 ('qaaaraaa')
RIP: 0x61616173 ('saaa')

[!] Crash Instruction: 0x401168 <main+38>: ret
[!] Overwritten RIP Value: 0x61616173 or 'saaa'
[!] Challenge Flag: flag{pwn_cyclic_eip_offset_control_7272}

INSTRUCTIONS FOR SHADOW CAT OPERATOR:
1. Go to ShadowSolve UI -> 'Binary & Pwn' menu -> 'Cyclic Offset Finder' tab.
2. Input '0x61616173' or 'saaa' in the Pattern field.
3. The engine will instantly calculate exact offset: 72 bytes.
4. Exploit padding string: 'A' * 72 + p64(win_addr)
"""
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Created: {txt_path.name}")

# 3. Multi-Stage CyberChef Bake Payload
def make_cyberchef_bake():
    txt_path = OUT_DIR / "challenge_3_cyberchef_bake.txt"
    raw_flag = "flag{cyberchef_multi_stage_recipe_unravel_5519}"
    
    # Stage 1: Base64 encode
    s1 = base64.b64encode(raw_flag.encode("utf-8")).decode("utf-8")
    # Stage 2: ROT13
    s2 = codecs.encode(s1, "rot_13")
    # Stage 3: Hex encode
    s3 = s2.encode("utf-8").hex()
    
    content = f"""=== ENCRYPTED OPERATOR TRANSMISSION ===
Encoded Payload (Hex -> ROT13 -> Base64):
{s3}

HOW TO SOLVE ON SHADOW CAT UI:
Method A (Automated):
  Go to 'Crypto' -> 'Magic Auto-Unwrap' -> Paste payload -> Click 'Magic Unwrap'
Method B (CyberChef Pipeline):
  Go to 'Crypto' -> 'CyberChef Studio'
  Recipe Steps:
    1. From Hex
    2. ROT13
    3. From Base64
  Click 'Bake Recipe' -> Reveals Flag: {raw_flag}
"""
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Created: {txt_path.name}")

# 4. CTF Challenge Description Classification Cases
def make_classify_cases():
    txt_path = OUT_DIR / "challenge_4_classify_cases.txt"
    content = """=== CTF CHALLENGE CLASSIFICATION BENCHMARKS ===
Test these prompts in ShadowSolve UI -> 'Classify' or 'Chat' to test AI/ML Auto-Categorization:

[CASE 1: PWN]
"We found a 32-bit x86 ELF binary running on port 1337 with buffer overflow in gets(). Can you help me find the offset to overwrite EIP and build a ret2libc ROP chain?"
Expected Category: pwn
Protection: NX Disabled, No Canary, No PIE

[CASE 2: CRYPTO]
"We intercepted RSA ciphertext c=... with modulus n=... and small public exponent e=3. Is this vulnerable to cube root or Hastad broadcast attack?"
Expected Category: crypto

[CASE 3: FORENSICS]
"Analyze this memory dump .raw image using Volatility to find active process tree, hidden dll injection, and carved files from unallocated clusters."
Expected Category: forensics

[CASE 4: REVERSE ENGINEERING]
"Decompile this stripped Go binary, locate main.checkPassword function, analyze byte array XOR loop, and bypass anti-debugging ptrace checks."
Expected Category: rev

[CASE 5: WEB EXPLOITATION]
"Target web app has SQL injection in id parameter and JWT token with alg: none vulnerability leading to admin privilege escalation."
Expected Category: web
"""
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Created: {txt_path.name}")

if __name__ == "__main__":
    print("=" * 60)
    print("[+] GENERATING CATEGORY 3 CTF CHALLENGE TEST FILES")
    print("=" * 60)
    make_vuln_pwn_binary()
    make_crash_telemetry()
    make_cyberchef_bake()
    make_classify_cases()
    print("=" * 60)
    print(f"[OK] Category 3 challenge files successfully saved to:")
    print(f"     {OUT_DIR}")
    print("=" * 60)
