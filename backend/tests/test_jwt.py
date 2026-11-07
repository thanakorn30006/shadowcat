import unittest
import sys
import json
import base64
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from routers.jwt_tool import b64_decode, b64_encode

class TestJWTEngine(unittest.TestCase):
    def test_b64_urlsafe_roundtrip(self):
        sample = b"shadowcat_jwt_payload_data"
        enc = b64_encode(sample)
        self.assertNotIn("=", enc)
        dec = b64_decode(enc)
        self.assertEqual(dec, sample.decode())

    def test_forge_alg_none(self):
        header = {"alg": "none", "typ": "JWT"}
        payload = {"user": "admin", "role": "superuser"}
        
        h_b64 = b64_encode(json.dumps(header).encode())
        p_b64 = b64_encode(json.dumps(payload).encode())
        forged = f"{h_b64}.{p_b64}."
        
        parts = forged.split(".")
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[2], "")
        
        parsed_h = json.loads(b64_decode(parts[0]))
        self.assertEqual(parsed_h["alg"], "none")

if __name__ == "__main__":
    unittest.main()
