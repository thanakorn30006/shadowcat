import unittest
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from routers.rsa import _parse_bigint
from core.ctf_agent import rsa_attack

class TestRSAEngine(unittest.TestCase):
    def test_parse_bigint_decimal(self):
        self.assertEqual(_parse_bigint("3233", "test"), 3233)
        self.assertEqual(_parse_bigint(3233, "test"), 3233)

    def test_parse_bigint_hex(self):
        self.assertEqual(_parse_bigint("0xca1", "test"), 0xca1)

    def test_parse_bigint_large_512bit(self):
        large_n_str = (
            "1187428489728795928682858718361250267448834789574768374972749582"
            "7485729475829475829475829374829374829374829374829374829374829374"
        )
        parsed = _parse_bigint(large_n_str, "large_n")
        self.assertIsInstance(parsed, int)
        self.assertEqual(str(parsed), large_n_str)

    def test_small_n_attack(self):
        # p=61, q=53, n=3233, e=17
        res = rsa_attack(3233, 17, 2790)
        self.assertIn("attacks", res)
        # Check that factorization produced p and q
        factoring = next((a for a in res["attacks"] if a["name"] == "Small N Factoring"), None)
        self.assertIsNotNone(factoring)
        self.assertIn("p", factoring)
        self.assertIn("q", factoring)
        self.assertIn(factoring["p"], [53, 61])
        self.assertIn(factoring["q"], [53, 61])

if __name__ == "__main__":
    unittest.main()
