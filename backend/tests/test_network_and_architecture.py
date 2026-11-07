import unittest
import asyncio
from fastapi.testclient import TestClient
from main import app
from core.burp_engine import burp_repeater_send, scan_target_vulnerabilities
from core.ctf_agent import search_flags

class TestNetworkAndArchitecture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_security_headers_present(self):
        """Verify all critical security headers are attached to API responses."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(resp.headers.get("x-frame-options"), "SAMEORIGIN")
        self.assertEqual(resp.headers.get("x-xss-protection"), "1; mode=block")
        self.assertEqual(resp.headers.get("referrer-policy"), "strict-origin-when-cross-origin")

    def test_cors_trusted_origin_accepted(self):
        """Verify localhost:3333 and localhost:8000 origins are allowed."""
        headers = {"Origin": "http://localhost:3333"}
        resp = self.client.get("/api/license/status", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("access-control-allow-origin"), "http://localhost:3333")
        self.assertEqual(resp.headers.get("access-control-allow-credentials"), "true")

    def test_cors_untrusted_origin_rejected(self):
        """Verify unauthorized external origins (e.g. evil.com) do NOT get access-control headers."""
        headers = {"Origin": "https://malicious-exploit-hub.com"}
        resp = self.client.get("/api/license/status", headers=headers)
        self.assertEqual(resp.status_code, 200)
        # Untrusted origin must not be reflected
        self.assertIsNone(resp.headers.get("access-control-allow-origin"))

    def test_flag_regex_extraction(self):
        """Verify automated CTF flag extraction logic for various standard formats."""
        sample_body = """
        User details leaked:
        FLAG: picoCTF{mock_pico_flag_1234}
        Backup: flag{standard_ctf_format_5678}
        HTB token: htb{hackthebox_vault_token}
        """
        flags = search_flags(sample_body)
        self.assertIn("picoCTF{mock_pico_flag_1234}", flags)
        self.assertIn("flag{standard_ctf_format_5678}", flags)
        self.assertIn("htb{hackthebox_vault_token}", flags)

if __name__ == '__main__':
    unittest.main()
