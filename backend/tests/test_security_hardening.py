import unittest
import tempfile
import os
import io
import zipfile
import tarfile
from pathlib import Path
from core.ctf_agent import try_extract
from core.config import UPLOAD_DIR

class TestSecurityHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_zip_slip_path_traversal_blocked(self):
        """Verify Zip Slip path traversal payloads cannot escape target destination."""
        zip_path = os.path.join(self.temp_dir, "malicious_zipslip.zip")
        extract_dest = os.path.join(self.temp_dir, "extracted_safe")
        os.makedirs(extract_dest, exist_ok=True)

        # Build malicious zip containing directory traversal member
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("safe_file.txt", "This is safe")
            z.writestr("../../escaped_file.txt", "ATTEMPTED_TRAVERSAL")

        result = try_extract(zip_path, extract_dest)
        self.assertTrue(result["success"])
        
        # Verify safe file was extracted
        self.assertTrue(os.path.exists(os.path.join(extract_dest, "safe_file.txt")))
        
        # Verify escaped file was blocked and never written outside extract_dest
        escaped_target = os.path.join(self.temp_dir, "escaped_file.txt")
        self.assertFalse(os.path.exists(escaped_target), "Security Failure: Escaped file was written outside target destination!")

    def test_tar_slip_path_traversal_blocked(self):
        """Verify Tar Slip path traversal payloads cannot escape target destination."""
        tar_path = os.path.join(self.temp_dir, "malicious_tarslip.tar")
        extract_dest = os.path.join(self.temp_dir, "extracted_tar")
        os.makedirs(extract_dest, exist_ok=True)

        with tarfile.open(tar_path, "w") as t:
            # Safe member
            data = b"Safe Tar Content"
            ti = tarfile.TarInfo("safe.txt")
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))

            # Unsafe traversal member
            ti_bad = tarfile.TarInfo("../tar_escaped.txt")
            bad_data = b"ATTEMPTED_TAR_TRAVERSAL"
            ti_bad.size = len(bad_data)
            t.addfile(ti_bad, io.BytesIO(bad_data))

        result = try_extract(tar_path, extract_dest)
        self.assertTrue(result["success"])
        
        # Verify escaped file is NOT outside
        escaped_file = os.path.join(self.temp_dir, "tar_escaped.txt")
        self.assertFalse(os.path.exists(escaped_file), "Security Failure: Tar traversal escaped destination!")

    def test_upload_dir_isolation(self):
        """Verify UPLOAD_DIR is located in user isolated home directory, not world-writable /tmp."""
        self.assertNotIn("/tmp/ctf_uploads", str(UPLOAD_DIR))
        self.assertTrue(str(UPLOAD_DIR).startswith(str(Path.home())))

if __name__ == '__main__':
    unittest.main()
