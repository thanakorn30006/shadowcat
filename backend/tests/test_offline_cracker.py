import unittest
import sys
import hashlib
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.offline_wordlist_cracker import init_offline_wordlist, crack_offline_hash

class TestOfflineCracker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_offline_wordlist()

    def test_crack_md5_password(self):
        # md5 of 'password'
        pw = "password"
        m5 = hashlib.md5(pw.encode()).hexdigest()
        res = crack_offline_hash(m5)
        self.assertIsNotNone(res)
        self.assertTrue(res["cracked"])
        self.assertEqual(res["plaintext"], pw)

    def test_crack_sha256_admin(self):
        # sha256 of 'admin'
        pw = "admin"
        s256 = hashlib.sha256(pw.encode()).hexdigest()
        res = crack_offline_hash(s256)
        self.assertIsNotNone(res)
        self.assertTrue(res["cracked"])
        self.assertEqual(res["plaintext"], pw)

if __name__ == "__main__":
    unittest.main()
