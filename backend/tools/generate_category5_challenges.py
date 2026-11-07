#!/usr/bin/env python3
"""
Generates Category 5 Challenge Test Files for ShadowSolve Web UI testing.
Targets:
1. challenge_1_opsec_memory_artifact.raw   -> Test Memory Carving & String Extraction
2. challenge_2_sensitive_leak_bundle.txt   -> Test Automated Secret & Token Hunting
3. challenge_3_confidential_hashes_opsec.txt -> Test Air-Gapped Hash Privacy & Blocked Outbound Signals
"""

import os
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent.parent / "test_challenges_category5"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# 1. Raw Memory Artifact (Carving & Air-Gapped Analysis)
def make_memory_artifact():
    raw_path = OUT_DIR / "challenge_1_opsec_memory_artifact.raw"
    
    # Simulate RAM dump segment with kernel structures and unallocated strings
    header = b"\x00" * 128
    header += b"PAGE_DUMP_V4_X86_64\x00\x00\x00\x00"
    
    body = b"\x90\xcc\x90\xcc" * 64
    body += b"Process: explorer.exe PID: 1420 PPID: 808\n"
    body += b"Process: chrome.exe PID: 3204 PPID: 1420\n"
    body += b"Auth Token: eyJhbGciOiJIUzI1NiJ9.secret_session.signature\n"
    body += b"Confidential Engagement Note: Air-gapped network assessment in progress.\n"
    body += b"Artifact Flag: flag{opsec_airgapped_memory_carved_8819}\n"
    
    footer = b"\x00" * 256
    content = header + body + footer
    
    raw_path.write_bytes(content)
    print(f"[+] Created: {raw_path.name}")

# 2. Sensitive Credential & Token Leak Bundle
def make_leak_bundle():
    bundle_path = OUT_DIR / "challenge_2_sensitive_leak_bundle.txt"
    content = """// Confidential Deployment Script & Web Assets
// Leaked internal developer credentials

const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const DB_CONNECTION = "postgres://redteam:supersecret@10.0.4.15:5432/opsec_vault";
const INTERNAL_API = "/api/v1/internal/admin/credentials";
const BEARER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.sig";

// Exfiltrated Mission Intelligence:
const OPSEC_FLAG = "flag{opsec_hardcoded_secret_token_leak_5521}";

function connectRemote() {
    fetch(INTERNAL_API, {
        headers: { "Authorization": "Bearer " + BEARER_TOKEN }
    });
}
"""
    bundle_path.write_text(content, encoding="utf-8")
    print(f"[+] Created: {bundle_path.name}")

# 3. Confidential Hashes & Air-Gapped Mode Verification
def make_confidential_hashes():
    hash_path = OUT_DIR / "challenge_3_confidential_hashes_opsec.txt"
    content = """=== OPSEC HASH PRIVACY BENCHMARKS ===
Test these hashes in ShadowSolve UI -> 'Hash Cracker':

[TEST A: Instant Offline Memory Crack]
Hash (MD5 of 'admin'):
21232f297a57a5a743894a0e4a801fc3
Result: Solved in < 0.00002 seconds without sending any packets outside!

[TEST B: Confidential Unknown Hash - Air-Gapped Outbound Blocking]
Hash:
d41d8cd98f00b204e9800998ecf8427e_custom_confidential_client_hash
Result with AIR_GAPPED=1:
ShadowSolve strictly BLOCKS requests to third-party public crack services (CrackStation, Gromweb, md5decrypt) to preserve data privacy and prevent secret leakage!
"""
    hash_path.write_text(content, encoding="utf-8")
    print(f"[+] Created: {hash_path.name}")

if __name__ == "__main__":
    print("=" * 60)
    print("[+] GENERATING CATEGORY 5 CTF CHALLENGE TEST FILES")
    print("=" * 60)
    make_memory_artifact()
    make_leak_bundle()
    make_confidential_hashes()
    print("=" * 60)
    print(f"[OK] Category 5 challenge files successfully saved to:")
    print(f"     {OUT_DIR}")
    print("=" * 60)
