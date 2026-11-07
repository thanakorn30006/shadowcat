#!/usr/bin/env python3
"""
Generates Category 4 Challenge Test Files for ShadowSolve Web UI testing.
Targets:
1. challenge_1_authentic_pro_license.lic   -> Test Ed25519 Asymmetric Verification
2. challenge_1_counterfeit_tampered.lic    -> Test Cryptographic Tamper-Proof Rejection
3. challenge_2_rsa_factoring.json          -> Test RSA Small N Factoring Attack
4. challenge_2_rsa_cube_root.json          -> Test RSA e=3 Low Public Exponent Attack
5. challenge_3_jwt_tokens.txt              -> Test JWT Weak HMAC Crack & alg: none Bypass
6. challenge_4_hashes_offline.txt          -> Test O(1) Offline RockYou Dictionary Cracker
"""

import sys
import json
import base64
import hmac
import hashlib
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.license_engine import sign_license

OUT_DIR = Path(__file__).resolve().parent.parent.parent / "test_challenges_category4"
OUT_DIR.mkdir(parents=True, exist_ok=True)

KEY_FILE = Path(__file__).resolve().parent.parent / "secrets" / "master_license_authority.key"
MASTER_KEY = KEY_FILE.read_text().strip() if KEY_FILE.exists() else "e836759402b40d55976cb8701249ad918190dd9bbfa3bad41b5825ee082bcf95"

# 1. Authentic & Tampered Licenses
def make_licenses():
    # 1A: Authentic Pro Floating License
    lic_text = sign_license(
        tier="PRO_OPERATOR",
        holder="Thanakorn — Elite RedTeam Lead",
        token="SHADOW-PRO-9921-8842-1109",
        hwid="ANY",
        issued="2026-11-07",
        private_key_hex=MASTER_KEY
    )
    lic_path = OUT_DIR / "challenge_1_authentic_pro_license.lic"
    lic_path.write_text(lic_text, encoding="utf-8")
    print(f"[+] Created: {lic_path.name}")

    # 1B: Counterfeit / Tampered License
    # Modify 1 single character in the holder name without having private key
    tampered_text = lic_text.replace("Thanakorn", "MaliciousAttacker_Hacked")
    tampered_path = OUT_DIR / "challenge_1_counterfeit_tampered.lic"
    tampered_path.write_text(tampered_text, encoding="utf-8")
    print(f"[+] Created: {tampered_path.name}")

# 2. RSA Challenge Datasets
def make_rsa_challenges():
    # 2A: Small N Factoring
    # p = 1000003, q = 1000033 (both are primes) -> n = 1000036000099
    p = 1000003
    q = 1000033
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    raw_secret = "win!"
    m1 = int.from_bytes(raw_secret.encode("utf-8"), "big")
    c1 = pow(m1, e, n)

    rsa_small_path = OUT_DIR / "challenge_2_rsa_factoring.json"
    with open(rsa_small_path, "w", encoding="utf-8") as f:
        json.dump({
            "title": "RSA Small N Factoring Challenge",
            "n": str(n),
            "e": str(e),
            "c": str(c1),
            "expected_p": p,
            "expected_q": q,
            "expected_d": d,
            "expected_plaintext": raw_secret,
            "instructions": "Go to 'Crypto' -> 'RSA Attacks' -> Paste n, e, c -> Click 'Execute Attacks' to factor n and derive private key d."
        }, f, indent=2)
    print(f"[+] Created: {rsa_small_path.name}")

    # 2B: e=3 Cube Root Attack (c < n)
    raw_flag_2 = "flag{rsa_cube_root_low_exponent_win_9912}"
    m2 = int.from_bytes(raw_flag_2.encode("utf-8"), "big")
    e2 = 3
    c2 = pow(m2, e2) # c = m^3 without modulus wrap
    n2 = c2 * 2 + 1000 # n > c

    rsa_cube_path = OUT_DIR / "challenge_2_rsa_cube_root.json"
    with open(rsa_cube_path, "w", encoding="utf-8") as f:
        json.dump({
            "title": "RSA e=3 Low Exponent Cube Root Challenge",
            "n": str(n2),
            "e": "3",
            "c": str(c2),
            "expected_flag": raw_flag_2,
            "instructions": "Go to 'Crypto' -> 'RSA Attacks' -> Paste n, e=3, c -> Click 'Execute Attacks'"
        }, f, indent=2)
    print(f"[+] Created: {rsa_cube_path.name}")

# 3. JWT Studio Tokens
def make_jwt_tokens():
    jwt_path = OUT_DIR / "challenge_3_jwt_tokens.txt"
    secret = "secret123"
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "user": "operator_guest",
        "role": "user",
        "secret_flag": "flag{jwt_weak_hmac_secret_cracked_7721}",
        "access": "read_only"
    }

    h_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip('=')
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
    msg = f"{h_b64}.{p_b64}".encode('utf-8')
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), msg, hashlib.sha256).digest()).decode().rstrip('=')
    token = f"{h_b64}.{p_b64}.{sig}"

    content = f"""=== JWT EXPLOITATION & ANALYSIS BENCHMARK ===

Target Token (Signed with weak dictionary secret '{secret}'):
{token}

HOW TO TEST ON SHADOW CAT UI:
1. Go to ShadowSolve UI -> 'JWT Studio'
2. Paste the token into the JWT Input box.
3. Click 'Decode & Inspect':
   - Result: Automatically cracks weak secret '{secret}'!
   - Result: Automatically forges 'alg: none' exploit token: {h_b64}.{p_b64}.
   - Reveals Target Flag: flag{{jwt_weak_hmac_secret_cracked_7721}}
4. Click 'Forge / Tamper':
   - Modify payload role to 'admin'
   - Click 'Forge Token' to generate elevated signature!
"""
    jwt_path.write_text(content, encoding="utf-8")
    print(f"[+] Created: {jwt_path.name}")

# 4. Offline RockYou Hash Cracker
def make_hash_samples():
    hash_path = OUT_DIR / "challenge_4_hashes_offline.txt"
    content = """=== OFFLINE HIGH-YIELD HASH CRACKING BENCHMARKS ===
Test these hashes in ShadowSolve UI -> 'Hash Cracker' (100% Offline in O(1) time):

1. MD5 Hash (Password: 'admin'):
   21232f297a57a5a743894a0e4a801fc3
   Expected Cracked Plaintext: admin

2. MD5 Hash (Password: '123456'):
   e10adc3949ba59abbe56e057f20f883e
   Expected Cracked Plaintext: 123456

3. SHA256 Hash (Password: 'admin'):
   8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
   Expected Cracked Plaintext: admin

4. SHA1 Hash (Password: 'password'):
   5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
   Expected Cracked Plaintext: password

5. NTLM Hash (Password: 'operator'):
   c99a6cf67f017e889b78a9c13e5ffb6c
   Expected Cracked Plaintext: operator
"""
    hash_path.write_text(content, encoding="utf-8")
    print(f"[+] Created: {hash_path.name}")

if __name__ == "__main__":
    print("=" * 60)
    print("[+] GENERATING CATEGORY 4 CTF CHALLENGE TEST FILES")
    print("=" * 60)
    make_licenses()
    make_rsa_challenges()
    make_jwt_tokens()
    make_hash_samples()
    print("=" * 60)
    print(f"[OK] Category 4 challenge files successfully saved to:")
    print(f"     {OUT_DIR}")
    print("=" * 60)
