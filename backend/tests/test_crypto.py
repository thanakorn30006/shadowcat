import unittest
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.ctf_agent import caesar_decode, vigenere_autocrack
from core.cyberchef_engine import calculate_shannon_entropy, execute_cyberchef_recipe, rot47, atbash_cipher

class TestCryptoEngines(unittest.TestCase):
    def test_caesar_decode(self):
        # Shift 13
        enc = "cvpbPGS{grfg}"
        dec = caesar_decode(enc, 13)
        self.assertEqual(dec, "picoCTF{test}")

    def test_rot47(self):
        text = "ShadowCat123"
        enc = rot47(text)
        dec = rot47(enc)
        self.assertEqual(dec, text)

    def test_atbash(self):
        text = "Hello"
        enc = atbash_cipher(text)
        dec = atbash_cipher(enc)
        self.assertEqual(dec, text)

    def test_shannon_entropy(self):
        # Low entropy: repeated byte
        low_ent = calculate_shannon_entropy(b"AAAAAAAAAAAAAAAA")
        self.assertEqual(low_ent["entropy"], 0.0)

        # High entropy: diverse bytes
        high_ent = calculate_shannon_entropy(bytes(range(256)))
        self.assertAlmostEqual(high_ent["entropy"], 8.0, places=1)

    def test_cyberchef_recipe_pipeline(self):
        # Pipeline: To Base64 -> From Base64
        initial = "CTF_CHALLENGE_FLAG"
        recipe = [
            {"op": "to base64"},
            {"op": "from base64"}
        ]
        res = execute_cyberchef_recipe(initial, recipe)
        self.assertIn("output", res)
        self.assertEqual(res["output"], initial)

if __name__ == "__main__":
    unittest.main()
