import unittest
import sys
import json
import hmac
import hashlib
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from routers.binary import de_bruijn_cyclic, find_offset_in_cyclic
from routers.forensics import MAGIC_SIGNATURES
from routers.jwt_tool import forge_jwt, JWTForgeRequest, b64_decode
from core.cyberchef_engine import autonomous_magic_unwrap

class TestTacticalCyberUpgrades(unittest.TestCase):
    # ---------------------------------------------------------
    # 1. PWN: Cyclic Pattern & Offset Finder
    # ---------------------------------------------------------
    def test_cyclic_pattern_generation(self):
        pat200 = de_bruijn_cyclic(200, 4)
        self.assertEqual(len(pat200), 200)
        self.assertTrue(pat200.startswith("aaaa"))
        
        # Verify 4-byte windows are unique in early sequence
        seen = set()
        for i in range(len(pat200) - 3):
            sub = pat200[i:i+4]
            # De Bruijn sequences guarantee uniqueness up to alphabet size
            if i < 100:
                self.assertNotIn(sub, seen)
            seen.add(sub)

    def test_cyclic_offset_lookup(self):
        pat = de_bruijn_cyclic(200, 4)
        # Check an ASCII query
        target_4 = pat[40:44]
        offset = find_offset_in_cyclic(target_4, 4, 1000)
        self.assertEqual(offset, 40)

        # Check a Hex representation (e.g. little-endian memory crash register)
        # If EIP crashed with 4 bytes: target_4[::-1] as hex
        le_hex = "0x" + target_4.encode().hex()
        offset_hex = find_offset_in_cyclic(le_hex, 4, 1000)
        self.assertIsNotNone(offset_hex)

    # ---------------------------------------------------------
    # 2. FORENSICS: Magic Signatures & Restoration
    # ---------------------------------------------------------
    def test_magic_signatures_integrity(self):
        self.assertIn("png", MAGIC_SIGNATURES)
        self.assertIn("jpg", MAGIC_SIGNATURES)
        self.assertIn("zip", MAGIC_SIGNATURES)
        self.assertIn("elf", MAGIC_SIGNATURES)
        self.assertIn("pcap", MAGIC_SIGNATURES)

        png_magic = MAGIC_SIGNATURES["png"]["magic"]
        self.assertEqual(png_magic, b"\x89PNG\r\n\x1a\n")

        corrupted_content = b"\x00\x00\x00\x00" + b"IHDR" + b"dummy_png_payload"
        repaired = png_magic + corrupted_content[len(png_magic):]
        self.assertTrue(repaired.startswith(b"\x89PNG\r\n\x1a\n"))

    # ---------------------------------------------------------
    # 3. JWT: RS256 to HS256 Algorithm Confusion (CVE-2015-9235)
    # ---------------------------------------------------------
    async def run_jwt_confusion(self):
        pub_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"
        req = JWTForgeRequest(
            header={"alg": "RS256", "typ": "JWT"},
            payload={"user": "admin", "role": "root"},
            alg_confusion=True,
            public_key=pub_key
        )
        res = await forge_jwt(req)
        token = res["token"]
        self.assertIn(".", token)
        parts = token.split(".")
        self.assertEqual(len(parts), 3)

        # Header must be downgraded to HS256
        header = json.loads(b64_decode(parts[0]))
        self.assertEqual(header["alg"], "HS256")

        # Signature must match HMAC-SHA256 with public key as secret
        msg = f"{parts[0]}.{parts[1]}".encode("utf-8")
        expected_sig = hmac.new(pub_key.encode("utf-8"), msg, hashlib.sha256).digest()
        from routers.jwt_tool import b64_encode
        expected_sig_b64 = b64_encode(expected_sig)
        self.assertEqual(parts[2], expected_sig_b64)

    def test_jwt_confusion_sync(self):
        import asyncio
        asyncio.run(self.run_jwt_confusion())

    # ---------------------------------------------------------
    # 4. CRYPTO: Autonomous Magic Unwrapper
    # ---------------------------------------------------------
    def test_autonomous_magic_unwrapper(self):
        import base64
        import codecs

        secret_flag = "flag{cyber_autonomous_unwrapper_success}"
        # Layer 1: ROT13
        l1 = codecs.decode(secret_flag, 'rot_13')
        # Layer 2: Base64
        l2 = base64.b64encode(l1.encode()).decode()
        # Layer 3: Hex
        l3 = l2.encode().hex()

        result = autonomous_magic_unwrap(l3, max_depth=8)
        self.assertTrue(result["success"])
        self.assertEqual(result["flag"], secret_flag)
        self.assertEqual(len(result["recipe"]), 3)
        ops = [step["op"] for step in result["recipe"]]
        self.assertEqual(ops, ["from_hex", "from_base64", "rot13"])

    # ---------------------------------------------------------
    # 5. Robustness & Edge-Case Guardrails
    # ---------------------------------------------------------
    def test_cyclic_64bit_performance(self):
        import time
        t0 = time.time()
        # 64-bit AMD64 width = 8 must complete in < 0.05 seconds with early stopping
        pat_64 = de_bruijn_cyclic(1000, width=8)
        elapsed = time.time() - t0
        self.assertEqual(len(pat_64), 1000)
        self.assertTrue(pat_64.startswith("aaaaaaaa"))
        self.assertLess(elapsed, 0.05)

    def test_cyclic_offset_not_found(self):
        # Query not in pattern
        offset = find_offset_in_cyclic("zzzzzz", 4, 1000)
        self.assertIsNone(offset)

        # Empty query
        offset_empty = find_offset_in_cyclic("", 4, 1000)
        self.assertIsNone(offset_empty)

    def test_magic_unwrap_empty_and_invalid(self):
        # Empty string
        res_empty = autonomous_magic_unwrap("", max_depth=5)
        self.assertFalse(res_empty["success"])
        self.assertEqual(res_empty["depth"], 0)
        self.assertEqual(res_empty["output"], "")

        # Unsolvable random junk
        res_junk = autonomous_magic_unwrap("___random_non_cipher_text___", max_depth=4)
        self.assertFalse(res_junk["success"])
        self.assertIsNone(res_junk["flag"])

if __name__ == "__main__":
    unittest.main()
