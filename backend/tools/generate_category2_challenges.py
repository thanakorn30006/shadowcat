#!/usr/bin/env python3
"""
Generates Category 2 Challenge Test Files for ShadowSolve Web UI testing.
Targets:
1. challenge_1_corrupted_header.png  -> Test Magic Byte Check & Repair
2. challenge_2_forensic_archive.zip  -> Test Safe Archive Extraction & Carving
3. challenge_3_stego_overlay.png     -> Test Deep Steganography & Strings
4. challenge_4_traffic.pcap          -> Test Wireshark PCAP Packet Dissection
5. challenge_5_vuln_elf.bin          -> Test Binary & Pwn Checksec / Disassembly
"""

import os
import struct
import zipfile
from pathlib import Path
from PIL import Image

OUT_DIR = Path(__file__).resolve().parent.parent.parent / "test_challenges_category2"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# 1. Corrupted Header Image (for Magic Header Repair)
def make_corrupted_png():
    img_path = OUT_DIR / "challenge_1_corrupted_header.png"
    # Create valid small 64x64 PNG in memory
    temp_img = OUT_DIR / "_temp.png"
    im = Image.new("RGB", (64, 64), color=(15, 23, 42))
    im.save(temp_img, format="PNG")
    with open(temp_img, "rb") as f:
        png_bytes = f.read()
    temp_img.unlink()

    # Corrupt the magic header bytes \x89PNG\r\n\x1a\n with bad bytes
    corrupted_bytes = b"CORRUPTED!" + png_bytes[10:] + b"\nflag{corrupted_magic_repaired_win_3389}\n"
    with open(img_path, "wb") as f:
        f.write(corrupted_bytes)
    print(f"[+] Created: {img_path.name}")

# 2. Forensic Archive (for Safe Archive Extraction & Artifact Carving)
def make_archive():
    zip_path = OUT_DIR / "challenge_2_forensic_archive.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("investigation_log.txt", "Forensics incident response report.\nOperator: ShadowCat Agent\n")
        zf.writestr("evidence/secret_note.txt", "Exfiltrated intelligence artifact.\nFlag: flag{zip_archive_extracted_artifact_5541}\n")
    print(f"[+] Created: {zip_path.name}")

# 3. Steganography Image (for Deep Stego / LSB & Overlay Engine)
def make_stego_png():
    img_path = OUT_DIR / "challenge_3_stego_overlay.png"
    im = Image.new("RGB", (100, 100), color=(16, 185, 129))
    im.save(img_path, format="PNG")
    # Append trailing overlay payload with magic and flag
    overlay_payload = b"\n--- ATTACHED EVIDENCE PAYLOAD ---\nflag{stego_lsb_bitplane_extracted_9122}\n"
    with open(img_path, "ab") as f:
        f.write(overlay_payload)
    print(f"[+] Created: {img_path.name}")

# 4. PCAP Packet Capture (for PCAP Analyzer)
def make_pcap():
    pcap_path = OUT_DIR / "challenge_4_traffic.pcap"
    # Global header (24 bytes): Little-endian PCAP
    global_hdr = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4, # Magic
        2, 4,       # Major, minor
        0, 0,       # Timezone, sigfigs
        65535,      # Snaplen
        1           # Linktype: Ethernet
    )

    # Ethernet + IP + TCP + HTTP payload
    payload = b"GET /admin?token=secret HTTP/1.1\r\nHost: ctf.local\r\nAuthorization: Basic ZmxhZzp7cGNhcH0=\r\nX-CTF-Flag: flag{pcap_packet_dissection_flag_8812}\r\n\r\n"
    
    # Fake packet headers
    # Eth (14 bytes)
    eth = b"\x00\x0c\x29\x1a\x2b\x3c\x00\x0c\x29\x4d\x5e\x6f\x08\x00"
    # IP (20 bytes): 192.168.1.50 -> 10.0.0.1
    ip_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 0x1234, 0, 64, 6, 0, socket.inet_aton("192.168.1.50"), socket.inet_aton("10.0.0.1"))
    # TCP (20 bytes): src 54321 -> dst 80
    tcp_hdr = struct.pack("!HHIIBBHHH", 54321, 80, 1000, 2000, 0x50, 0x18, 64240, 0, 0)
    
    pkt_data = eth + ip_hdr + tcp_hdr + payload
    pkt_len = len(pkt_data)
    
    pkt_hdr = struct.pack("<IIII", 1600000000, 0, pkt_len, pkt_len)
    
    with open(pcap_path, "wb") as f:
        f.write(global_hdr + pkt_hdr + pkt_data)
    print(f"[+] Created: {pcap_path.name}")

# 5. ELF Executable Binary (for Binary & Pwn Checksec / Disassembly)
def make_vuln_elf():
    elf_path = OUT_DIR / "challenge_5_vuln_elf.bin"
    
    # Minimal valid 64-bit ELF header
    # e_ident: 16 bytes: \x7fELF, 2 (64-bit), 1 (LE), 1 (version), 0 (System V), 0 (padding...)
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    
    # ELF Header fields (64-bit):
    # type=2 (EXEC), machine=0x3E (x86_64), version=1, entry=0x401000, phoff=64, shoff=0, flags=0
    # ehsize=64, phentsize=56, phnum=1, shentsize=64, shnum=0, shstrndx=0
    elf_hdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        2,      # ET_EXEC (No PIE)
        0x3E,   # EM_X86_64
        1,      # EV_CURRENT
        0x401000, # Entry
        64,     # phoff
        0,      # shoff
        0,      # flags
        64,     # ehsize
        56,     # phentsize
        1,      # phnum
        64,     # shentsize
        0, 0
    )
    
    # Program Header: PT_LOAD, r-x
    # p_type=1 (LOAD), p_flags=5 (R|X), p_offset=0, p_vaddr=0x400000, p_paddr=0x400000, p_filesz=512, p_memsz=512, p_align=0x1000
    prog_hdr = struct.pack(
        "<IIQQQQQQ",
        1, 5, 0, 0x400000, 0x400000, 512, 512, 0x1000
    )
    
    # Embed symbols and dangerous function names for checksec detection
    body = b"\x90" * 32
    body += b"gets\x00system\x00strcpy\x00puts\x00printf\x00"
    body += b"\nFlag: flag{binary_checksec_elf_inspected_7743}\n"
    body += b"\x00" * (512 - len(elf_hdr) - len(prog_hdr) - len(body))
    
    with open(elf_path, "wb") as f:
        f.write(elf_hdr + prog_hdr + body)
    print(f"[+] Created: {elf_path.name}")

if __name__ == "__main__":
    import socket
    print("=" * 60)
    print("[+] GENERATING CATEGORY 2 CTF CHALLENGE TEST FILES")
    print("=" * 60)
    make_corrupted_png()
    make_archive()
    make_stego_png()
    make_pcap()
    make_vuln_elf()
    print("=" * 60)
    print(f"[OK] All test files successfully saved to:")
    print(f"     {OUT_DIR}")
    print("=" * 60)
