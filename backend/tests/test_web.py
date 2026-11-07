import unittest
import sys
import asyncio
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.waf_engine import mutate_payload_variants
from core.js_hunter import analyze_target_js

class TestWebEngines(unittest.TestCase):
    def test_waf_mutation(self):
        payload = "' UNION SELECT 1,2,3--"
        variants = mutate_payload_variants(payload)
        self.assertGreater(len(variants), 3)
        # Verify comment splitting or hex encoding exists in variants
        has_bypass = any("/*" in v["payload"] or "%" in v["payload"] or "UnIoN" in v["payload"] for v in variants)
        self.assertTrue(has_bypass)

    def test_js_hunter_extraction(self):
        js_code = """
        const API_ENDPOINT = "/api/v2/auth/login";
        const apiKey = "AIzaSyD_Test_Dummy_Key_123456789";
        """
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(analyze_target_js("", js_code))
        loop.close()

        self.assertIn("endpoints", res)
        self.assertIn("secrets", res)
        self.assertTrue(any("/api/v2/auth/login" in ep for ep in res["endpoints"]))

if __name__ == "__main__":
    unittest.main()
