import sys, os, uuid, hashlib, re, datetime
from typing import Optional, Dict, Any, Tuple
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# -------------------------------------------------------------
# SHADOW CAT MASTER ASYMMETRIC PUBLIC KEY (Ed25519)
# Used for 100% offline signature verification without phoning home
# -------------------------------------------------------------
MASTER_PUBLIC_KEY_HEX = "f0c7dbc0e126b05d6f1e122ebbe6336f7cce0d0055b3d63665ffae6ac5d931f3"

def get_machine_id() -> str:
    """
    Computes a deterministic local hardware fingerprint (Node HWID)
    derived from hardware MAC address and system platform architecture.
    """
    try:
        raw_node = str(uuid.getnode())
        platform_info = f"{sys.platform}:{os.name}"
        combined = f"{raw_node}:{platform_info}".encode("utf-8")
        h = hashlib.sha256(combined).hexdigest()[:16].upper()
        return f"HWID-{h[:4]}-{h[4:8]}-{h[8:12]}-{h[12:16]}"
    except Exception:
        return "HWID-GENERIC-NODE-0001"

def build_canonical_message(tier: str, holder: str, issued: str, hwid: str, token: str) -> bytes:
    """
    Builds the immutable canonical byte sequence required for Ed25519 signing and verification.
    """
    canonical_str = (
        f"Tier:{tier.strip()}\n"
        f"Holder:{holder.strip()}\n"
        f"Issued:{issued.strip()}\n"
        f"HardwareID:{hwid.strip()}\n"
        f"Token:{token.strip()}"
    )
    return canonical_str.encode("utf-8")

def parse_license_text(content: str) -> Dict[str, str]:
    """
    Parses a PEM-style license file into key-value pairs.
    """
    data = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("-----"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip().lower()] = v.strip()
    return data

def verify_license_content(content: str, public_key_hex: str = MASTER_PUBLIC_KEY_HEX) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Verifies an Ed25519 cryptographic license string.
    Returns (is_valid, reason, metadata_dict).
    """
    if not content or not content.strip():
        return False, "Empty license content", {}

    parsed = parse_license_text(content)
    required_fields = ["tier", "holder", "issued", "signature"]
    for req in required_fields:
        if req not in parsed:
            return False, f"Missing required license field: '{req}'", {}

    tier = parsed.get("tier", "COMMUNITY").upper()
    holder = parsed.get("holder", "unknown")
    issued = parsed.get("issued", "")
    hwid = parsed.get("hardwareid", "ANY")
    token = parsed.get("token", "")
    sig_hex = parsed.get("signature", "")

    # Check Hardware ID binding if specified
    current_hwid = get_machine_id()
    if hwid not in ["ANY", "PORTABLE", "FLOATING", "*"]:
        if hwid != current_hwid:
            return False, f"Hardware ID mismatch: license bound to '{hwid}', this machine is '{current_hwid}'", {
                "tier": tier,
                "holder": holder,
                "required_hwid": hwid,
                "current_hwid": current_hwid
            }

    # Verify Ed25519 Signature
    try:
        sig_bytes = bytes.fromhex(sig_hex)
        pub_bytes = bytes.fromhex(public_key_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception as e:
        return False, f"Malformed signature or public key: {str(e)}", {}

    canonical_bytes = build_canonical_message(tier, holder, issued, hwid, token)

    try:
        public_key.verify(sig_bytes, canonical_bytes)
    except InvalidSignature:
        return False, "Cryptographic signature validation failed. License key has been tampered with or is counterfeit.", {}
    except Exception as e:
        return False, f"Verification error: {str(e)}", {}

    return True, "Valid Cryptographic License", {
        "tier": tier,
        "holder": holder,
        "issued": issued,
        "hardware_id": hwid,
        "token": token,
        "pro_features": (tier == "PRO_OPERATOR"),
        "signature_valid": True
    }

def sign_license(
    tier: str = "PRO_OPERATOR",
    holder: str = "operator@redteam-security.org",
    token: str = "SHADOW-PRO-7C2B-4E1D-5A6C",
    hwid: str = "ANY",
    issued: str = "",
    private_key_hex: str = ""
) -> str:
    """
    Authoring / Keygen routine: Signs canonical license data using Ed25519 private key.
    """
    if not issued:
        issued = datetime.date.today().isoformat()

    if not private_key_hex:
        raise ValueError("Private key is required to issue cryptographic licenses.")

    priv_bytes = bytes.fromhex(private_key_hex)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    canonical_bytes = build_canonical_message(tier, holder, issued, hwid, token)
    signature = private_key.sign(canonical_bytes)
    sig_hex = signature.hex()

    license_pem = (
        f"-----BEGIN SHADOWCAT LICENSE-----\n"
        f"Tier: {tier}\n"
        f"Holder: {holder}\n"
        f"Issued: {issued}\n"
        f"HardwareID: {hwid}\n"
        f"Token: {token}\n"
        f"Signature: {sig_hex}\n"
        f"-----END SHADOWCAT LICENSE-----"
    )
    return license_pem
