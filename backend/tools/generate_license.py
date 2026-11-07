#!/usr/bin/env python3
import sys, os, argparse
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.license_engine import sign_license, verify_license_content, get_machine_id

def main():
    parser = argparse.ArgumentParser(description="SHADOW CAT Offline Ed25519 License Issuer CLI")
    parser.add_argument("--holder", default="operator@redteam-security.org", help="License holder email or organization")
    parser.add_argument("--tier", default="PRO_OPERATOR", choices=["COMMUNITY", "PRO_OPERATOR", "ENTERPRISE_TEAM"])
    parser.add_argument("--hwid", default="ANY", help="Hardware ID to bind (or 'ANY' for portable floating license)")
    parser.add_argument("--token", default="SHADOW-PRO-7C2B-4E1D-5A6C", help="License token ID")
    parser.add_argument("--output", "-o", default="shadowcat.lic", help="Output file path")
    parser.add_argument("--show-hwid", action="store_true", help="Display this machine's Hardware ID and exit")

    args = parser.parse_args()

    if args.show_hwid:
        print(f"Current Machine HWID: {get_machine_id()}")
        return

    key_path = Path(__file__).parent.parent / "secrets" / "master_license_authority.key"
    if not key_path.is_file():
        print(f"Error: Master authority private key not found at {key_path}")
        sys.exit(1)

    priv_hex = key_path.read_text(encoding="utf-8").strip()

    lic_text = sign_license(
        tier=args.tier,
        holder=args.holder,
        token=args.token,
        hwid=args.hwid,
        private_key_hex=priv_hex
    )

    out_path = Path(args.output)
    out_path.write_text(lic_text, encoding="utf-8")
    print(f"[+] License successfully generated and cryptographically signed with Ed25519.")
    print(f"[+] Written to: {out_path.resolve()}")

    # Self-verify check
    valid, reason, meta = verify_license_content(lic_text)
    print(f"[+] Verification Check: {'VALID' if valid else 'FAILED'} ({reason})")

if __name__ == "__main__":
    main()
