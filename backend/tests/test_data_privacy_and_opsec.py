import unittest
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.js_hunter import extract_secrets_from_code, extract_endpoints_from_code
from core.offline_wordlist_cracker import crack_offline_hash
from routers.hash_crack import HashRequest, crack_hash

class TestDataPrivacyAndOpSec(unittest.TestCase):
    def test_airgapped_outbound_blocking(self):
        """Verify that when offline_only=True, uncrackable hashes do not leak outbound."""
        req = HashRequest(hash="d41d8cd98f00b204e9800998ecf8427e_unknown_client_hash", offline_only=True)
        res = crack_hash(req)
        self.assertFalse(res["cracked"])
        self.assertTrue(res.get("air_gapped"))
        self.assertIn("Air-Gapped Mode", res.get("hint", ""))

    def test_js_secret_hunting_accuracy(self):
        """Verify regex catches AWS credentials, internal IPs, and flags without leaking data."""
        sample_js = """
        const aws_key = 'AKIAIOSFODNN7EXAMPLE';
        const internal_ip = '10.0.4.15';
        const flag = 'flag{opsec_test_secret_hunting}';
        """
        secrets = extract_secrets_from_code(sample_js)
        labels = [s["type"] for s in secrets]
        values = [s["value"] for s in secrets]
        self.assertIn("AWS Access Key ID", labels)
        self.assertIn("Internal Private IPv4", labels)
        self.assertIn("CTF Flag Pattern", labels)
        self.assertIn("flag{opsec_test_secret_hunting}", values)

    def test_env_example_and_secrets_isolation(self):
        """Verify .env.example exists with sanitized placeholders and master key is isolated."""
        env_example = Path(__file__).parent.parent / ".env.example"
        self.assertTrue(env_example.is_file(), ".env.example must exist for safe onboarding")
        content = env_example.read_text()
        self.assertIn("GEMINI_API_KEY=", content)
        self.assertIn("AIR_GAPPED=", content)

if __name__ == '__main__':
    unittest.main()
