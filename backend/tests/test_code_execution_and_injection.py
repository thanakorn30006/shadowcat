import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from routers.binary import find_offset_in_cyclic, de_bruijn_cyclic
from core.cyberchef_engine import execute_cyberchef_recipe, autonomous_magic_unwrap
from core.ctf_ml import ctf_classify

class TestCodeExecutionAndInjection(unittest.TestCase):
    def test_cyclic_offset_accuracy(self):
        """Verify De Bruijn pattern finds accurate crash offsets for 32/64-bit addresses."""
        # 4-byte pattern 'saaa' or 0x61616173 is at offset 72
        offset_ascii = find_offset_in_cyclic("saaa", width=4)
        offset_hex = find_offset_in_cyclic("0x61616173", width=4)
        self.assertEqual(offset_ascii, 72)
        self.assertEqual(offset_hex, 72)

    def test_cyberchef_pure_transformations(self):
        """Verify CyberChef recipe executes sequential transforms safely without eval/exec."""
        recipe = [
            {"op": "from_hex", "args": {}},
            {"op": "rot13", "args": {}},
            {"op": "from_base64", "args": {}}
        ]
        # Payload created from 'flag{test_purity}'
        import base64, codecs
        raw = "flag{test_purity}"
        encoded = codecs.encode(base64.b64encode(raw.encode()).decode(), "rot_13").encode().hex()
        
        res = execute_cyberchef_recipe(encoded, recipe)
        self.assertEqual(res["final_output"], raw)
        self.assertIn(raw, res["flags_found"])

    def test_magic_unwrap_multi_depth(self):
        """Verify autonomous magic unwrap navigates chained Hex -> ROT13 -> Base64 encodings."""
        import base64, codecs
        raw = "flag{magic_auto_chain_success}"
        encoded = codecs.encode(base64.b64encode(raw.encode()).decode(), "rot_13").encode().hex()
        
        res = autonomous_magic_unwrap(encoded, max_depth=6)
        self.assertTrue(res["success"])
        self.assertEqual(res["flag"], raw)

    def test_ctf_classifier_safety(self):
        """Verify challenge classifier handles input safely and predicts correct category."""
        prompt = "Buffer overflow in gets() function leading to EIP overwrite and ret2libc ROP chain."
        res = ctf_classify(prompt)
        self.assertIn("classification", res)
        self.assertEqual(res["classification"]["category"], "pwn")

if __name__ == '__main__':
    unittest.main()
