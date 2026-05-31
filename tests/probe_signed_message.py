"""Discover what message Transmit signs in transmit_platform_device_validation.

Try many candidate messages against PSS-SHA256 salt=32 (and a few alternates).
"""
from __future__ import annotations

import base64
import hashlib
import itertools
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from crypto_utils import public_key_from_spki_b64

DEVICE_PUBLIC_KEY_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvC8fQkWa4xBgDx0k7IQrOcFEJvmv"
    "6V3nJuWr0B3CEE3cz6eDRbFsPJGNANNTk4CoRgWv7TNMdOrYtPfPO52STzasjbX6Zn6byGaj"
    "33lVxLU5juEsTyXFx1utbpaHU4ZqJlDPKAH1zAIv/ujf23uBSaG8TPTs/Fvl8uSQ1Hfbj6i0"
    "7orl/JeiUHj7Pi+ITQuSP10H4veSXzQ0rbx8LTzCzBle7/CBXmFyosd7EbbQkKuAFPgmLaSI"
    "ZlJr1No3UywBpT0OYT4nmA3zzmc0cBLuGwcidOMQMgIoNb5/Y15xcU8XIxo7X+JiiquZu6Am"
    "3HSYRNAcqGL4wdKWfit8QJPGAQIDAQAB"
)

# from HAR #20 response and #22 request
device_challenge_b64 = "+ZJCtUf7zFuHxxgBAtSN7w=="
fch_b64 = "96EeEa2dt7LO+m+UWzzG/IJu"
assertion_id = "igBgXPRnPqunre2V05oYzcYw"
platform_device_id_hex = "798cd11799148820181bf69c7deff51e34c761f73364e7780b9022ab872b12e5"
correlation_id = "df8fc34d-9b17-441c-892c-d8768d9eba40"
ephemeral_uid = "eph_34dc8dce-15ac-4749-8798-65ef96c38e93"
session_id = "f9683673-8831-4654-aadd-bb78b99ce241"
device_id = "699ccb8c-2ab1-4ba6-8e69-fbcd3a60ad12"

# from HAR #22 request
SIGNATURE_B64 = (
    "m7LFjJ5xiIrgwVZTfP11CQF7F9ouNPzfY43n4B0SU/fWBS6vetPcy4s9R5YWgFCZ5bFS/JfM"
    "PYmvMJeQdsYYvgO3oIR5edwdCvSKUVkuwq4jmXl5Nqk8Hhn6BN4iF/6/gNAmQdu7gTOBqGbA"
    "mz28wbf1Ov7LQC8IRcWIgaHA546sF30sl5dIX5x29dbkhQeJIJ4Q2qd5x8orlS3nc95S8DkB"
    "8oyl1j4x2xJ3loLoIo0zmFNWFUhehWAxS67Fr2BUuimQdC81XF/6vshAU2PrAgF1HUMuypBm"
    "lXUeFB9ptsvyUljoJSkdj4tXqHV1a5S+kUs+XaTHitwfxYX/IXdevw=="
)

pub = public_key_from_spki_b64(DEVICE_PUBLIC_KEY_B64)
sig = base64.b64decode(SIGNATURE_B64)

ch_raw = base64.b64decode(device_challenge_b64)  # 16 bytes
fch_raw = base64.b64decode(fch_b64)  # 16 bytes


def s(label: str, msg: bytes) -> None:
    """Try several padding variants over msg."""
    variants = [
        ("PSS-SHA256-s32", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()),
        ("PSS-SHA256-s0", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0), hashes.SHA256()),
        ("PSS-SHA256-sMAX", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()),
        ("PSS-SHA1-s20", padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=20), hashes.SHA1()),
        ("PKCS1v15-SHA256", padding.PKCS1v15(), hashes.SHA256()),
        ("PKCS1v15-SHA1", padding.PKCS1v15(), hashes.SHA1()),
    ]
    for name, pad, hsh in variants:
        try:
            pub.verify(sig, msg, pad, hsh)
            print(f"  *** MATCH: {label!r:<60} -> {name}")
            return
        except InvalidSignature:
            pass


# Candidate messages
candidates: list[tuple[str, bytes]] = []

# Raw bytes
candidates.append(("ch_raw (16B)", ch_raw))
candidates.append(("fch_raw (16B)", fch_raw))
candidates.append(("ch_raw + fch_raw", ch_raw + fch_raw))
candidates.append(("fch_raw + ch_raw", fch_raw + ch_raw))

# ASCII of b64 string
candidates.append(("ch_b64 ascii", device_challenge_b64.encode()))
candidates.append(("fch_b64 ascii", fch_b64.encode()))
candidates.append(("ch_b64 + fch_b64", (device_challenge_b64 + fch_b64).encode()))
candidates.append(("fch_b64 + ch_b64", (fch_b64 + device_challenge_b64).encode()))
candidates.append(("ch_b64.fch_b64", f"{device_challenge_b64}.{fch_b64}".encode()))
candidates.append(("fch_b64.ch_b64", f"{fch_b64}.{device_challenge_b64}".encode()))

# Mixed
candidates.append(("ch_raw + assertion_id ascii", ch_raw + assertion_id.encode()))
candidates.append(("ch_b64 + assertion_id", (device_challenge_b64 + assertion_id).encode()))
candidates.append(("ch_b64|fch_b64|assertion_id", f"{device_challenge_b64}|{fch_b64}|{assertion_id}".encode()))

# With platform_device_id
candidates.append(("ch_raw + pdid_hex", ch_raw + platform_device_id_hex.encode()))
candidates.append(("ch_raw + pdid_bytes", ch_raw + bytes.fromhex(platform_device_id_hex)))
candidates.append(("ch_b64 + pdid_hex", (device_challenge_b64 + platform_device_id_hex).encode()))

# With correlation_id / session ids
candidates.append(("ch_b64 + correlation_id", (device_challenge_b64 + correlation_id).encode()))
candidates.append(("ch_b64 + ephemeral_uid", (device_challenge_b64 + ephemeral_uid).encode()))
candidates.append(("ch_b64 + session_id", (device_challenge_b64 + session_id).encode()))
candidates.append(("ch_b64 + device_id", (device_challenge_b64 + device_id).encode()))

# JSON variants
input_obj = {"device_challenge": device_challenge_b64}
candidates.append(("json(input)", json.dumps(input_obj, separators=(",", ":")).encode()))
candidates.append(("json(input) spaces", json.dumps(input_obj).encode()))

# Maybe over a SHA-256 hash already
candidates.append(("sha256(ch_raw)", hashlib.sha256(ch_raw).digest()))
candidates.append(("sha256(fch_raw + ch_raw)", hashlib.sha256(fch_raw + ch_raw).digest()))

# Combinations of all relevant strings
all_b64_combos = list(itertools.permutations([device_challenge_b64, fch_b64, assertion_id], 2))
for a, b in all_b64_combos:
    candidates.append((f"{a}|{b}", f"{a}{b}".encode()))
    candidates.append((f"{a}.{b}", f"{a}.{b}".encode()))

print(f"Trying {len(candidates)} candidate messages...")
for label, msg in candidates:
    s(label, msg)
print("done.")
