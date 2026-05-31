"""
Golden test: confirms the signing algorithm used by Transmit Security's
`transmit_platform_device_validation` assertion matches the captured HAR.

Inputs are taken verbatim from `checkclient.har` entries #20 (request) and #22
(request body — contains `signature` over `device_challenge`).
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from crypto_utils import (
    device_key_id_from_spki_b64,
    public_key_from_spki_b64,
    verify_pss_sha256,
)

DEVICE_PUBLIC_KEY_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvC8fQkWa4xBgDx0k7IQrOcFEJvmv"
    "6V3nJuWr0B3CEE3cz6eDRbFsPJGNANNTk4CoRgWv7TNMdOrYtPfPO52STzasjbX6Zn6byGaj"
    "33lVxLU5juEsTyXFx1utbpaHU4ZqJlDPKAH1zAIv/ujf23uBSaG8TPTs/Fvl8uSQ1Hfbj6i0"
    "7orl/JeiUHj7Pi+ITQuSP10H4veSXzQ0rbx8LTzCzBle7/CBXmFyosd7EbbQkKuAFPgmLaSI"
    "ZlJr1No3UywBpT0OYT4nmA3zzmc0cBLuGwcidOMQMgIoNb5/Y15xcU8XIxo7X+JiiquZu6Am"
    "3HSYRNAcqGL4wdKWfit8QJPGAQIDAQAB"
)
EXPECTED_DEVICE_KEY_ID = "798cd11799148820181bf69c7deff51e34c761f73364e7780b9022ab872b12e5"
DEVICE_CHALLENGE_B64 = "+ZJCtUf7zFuHxxgBAtSN7w=="
SIGNATURE_B64 = (
    "m7LFjJ5xiIrgwVZTfP11CQF7F9ouNPzfY43n4B0SU/fWBS6vetPcy4s9R5YWgFCZ5bFS/JfM"
    "PYmvMJeQdsYYvgO3oIR5edwdCvSKUVkuwq4jmXl5Nqk8Hhn6BN4iF/6/gNAmQdu7gTOBqGbA"
    "mz28wbf1Ov7LQC8IRcWIgaHA546sF30sl5dIX5x29dbkhQeJIJ4Q2qd5x8orlS3nc95S8DkB"
    "8oyl1j4x2xJ3loLoIo0zmFNWFUhehWAxS67Fr2BUuimQdC81XF/6vshAU2PrAgF1HUMuypBm"
    "lXUeFB9ptsvyUljoJSkdj4tXqHV1a5S+kUs+XaTHitwfxYX/IXdevw=="
)


def test_device_key_id_matches_pubkey_hash() -> None:
    got = device_key_id_from_spki_b64(DEVICE_PUBLIC_KEY_B64)
    assert got == EXPECTED_DEVICE_KEY_ID, (
        f"device_key_id mismatch.\n  expected: {EXPECTED_DEVICE_KEY_ID}\n  got:      {got}"
    )
    print(f"  [PASS] device_key_id = sha256(SPKI) = {got}")


def test_signature_verifies_under_pss_sha256_salt32_over_b64_ascii() -> None:
    """The message signed is the ASCII bytes of the base64 challenge string itself
    (with `==` padding), not the decoded bytes. Found via probe_signed_message.py."""
    pub = public_key_from_spki_b64(DEVICE_PUBLIC_KEY_B64)
    sig = base64.b64decode(SIGNATURE_B64)
    msg = DEVICE_CHALLENGE_B64.encode("ascii")
    assert verify_pss_sha256(pub, sig, msg, salt_length=32), (
        "signature did NOT verify under RSA-PSS SHA-256 salt=32 over ASCII b64 challenge"
    )
    print(f"  [PASS] RSA-PSS SHA-256 salt=32 verifies signature over ASCII b64 challenge ({len(msg)} bytes)")


def _try_variants() -> None:
    """Fallback diagnostics: try other padding/hash/salt combos if the canonical one fails.

    Only runs if you call this manually — it's a debugging aid.
    """
    pub = public_key_from_spki_b64(DEVICE_PUBLIC_KEY_B64)
    sig = base64.b64decode(SIGNATURE_B64)
    challenge = base64.b64decode(DEVICE_CHALLENGE_B64)

    candidates = []
    for salt in (0, 20, 32, 48, 64, padding.PSS.MAX_LENGTH):
        candidates.append(("PSS-SHA256", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt), hashes.SHA256(), challenge))
        candidates.append(("PSS-SHA1", padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=salt), hashes.SHA1(), challenge))
    candidates.append(("PKCS1v15-SHA256", padding.PKCS1v15(), hashes.SHA256(), challenge))
    candidates.append(("PKCS1v15-SHA1", padding.PKCS1v15(), hashes.SHA1(), challenge))

    for label, pad, hsh, msg in candidates:
        try:
            pub.verify(sig, msg, pad, hsh)
            print(f"  [MATCH] {label} salt={getattr(pad, '_salt_length', '-')}")
        except InvalidSignature:
            pass


if __name__ == "__main__":
    failed = False
    for name, fn in [
        ("test_device_key_id_matches_pubkey_hash", test_device_key_id_matches_pubkey_hash),
        ("test_signature_verifies_under_pss_sha256_salt32_over_b64_ascii", test_signature_verifies_under_pss_sha256_salt32_over_b64_ascii),
    ]:
        print(f"-> {name}")
        try:
            fn()
        except AssertionError as e:
            failed = True
            print(f"  [FAIL] {e}")

    if failed:
        print()
        print("Canonical config failed. Probing variants:")
        _try_variants()
        sys.exit(1)
    print()
    print("All golden tests passed.")
