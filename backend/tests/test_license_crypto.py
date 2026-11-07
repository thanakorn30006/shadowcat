import unittest
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.license_engine import (
    sign_license,
    verify_license_content,
    get_machine_id,
    MASTER_PUBLIC_KEY_HEX
)

class TestCryptographicLicenseEngine(unittest.TestCase):
    def setUp(self):
        # Load master authority private key for test key issuance
        key_path = Path(__file__).parent.parent / "secrets" / "master_license_authority.key"
        self.priv_hex = key_path.read_text(encoding="utf-8").strip()

    def test_valid_floating_license(self):
        lic = sign_license(
            tier="PRO_OPERATOR",
            holder="redteam@enterprise-defense.org",
            token="SHADOW-PRO-TEST-001",
            hwid="ANY",
            issued="2026-11-06",
            private_key_hex=self.priv_hex
        )
        valid, reason, meta = verify_license_content(lic)
        self.assertTrue(valid)
        self.assertEqual(meta["tier"], "PRO_OPERATOR")
        self.assertEqual(meta["holder"], "redteam@enterprise-defense.org")
        self.assertTrue(meta["pro_features"])
        self.assertTrue(meta["signature_valid"])

    def test_tampered_content_fails(self):
        lic = sign_license(
            tier="PRO_OPERATOR",
            holder="legit@corp.com",
            token="SHADOW-PRO-VALID-001",
            hwid="ANY",
            issued="2026-11-06",
            private_key_hex=self.priv_hex
        )
        # Malicious user tampers holder email while keeping same signature
        tampered = lic.replace("Holder: legit@corp.com", "Holder: attacker@darknet.io")
        valid, reason, meta = verify_license_content(tampered)
        self.assertFalse(valid)
        self.assertIn("tampered", reason.lower())

    def test_counterfeit_signature_fails(self):
        fake_lic = """-----BEGIN SHADOWCAT LICENSE-----
Tier: PRO_OPERATOR
Holder: pirate@somewhere.com
Issued: 2026-11-06
HardwareID: ANY
Token: SHADOW-PRO-FAKE-1234
Signature: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
-----END SHADOWCAT LICENSE-----"""
        valid, reason, meta = verify_license_content(fake_lic)
        self.assertFalse(valid)
        self.assertIn("tampered", reason.lower())

    def test_node_locked_license_hwid_match(self):
        local_hwid = get_machine_id()
        # License bound to this machine
        lic = sign_license(
            tier="PRO_OPERATOR",
            holder="local@workstation.com",
            token="SHADOW-PRO-LOCKED-001",
            hwid=local_hwid,
            issued="2026-11-06",
            private_key_hex=self.priv_hex
        )
        valid, reason, meta = verify_license_content(lic)
        self.assertTrue(valid)

        # License bound to a DIFFERENT machine must fail
        foreign_lic = sign_license(
            tier="PRO_OPERATOR",
            holder="foreign@other.com",
            token="SHADOW-PRO-FOREIGN-001",
            hwid="HWID-DEAD-BEEF-CAFE-9999",
            issued="2026-11-06",
            private_key_hex=self.priv_hex
        )
        foreign_valid, foreign_reason, foreign_meta = verify_license_content(foreign_lic)
        self.assertFalse(foreign_valid)
        self.assertIn("hardware id mismatch", foreign_reason.lower())

    def test_empty_or_malformed_license(self):
        valid, reason, _ = verify_license_content("")
        self.assertFalse(valid)

        valid2, reason2, _ = verify_license_content("not a valid license content")
        self.assertFalse(valid2)

if __name__ == "__main__":
    unittest.main()
