from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jwk_to_private_key(jwk: dict[str, Any]) -> rsa.RSAPrivateKey:
    def n(k: str) -> int:
        return int.from_bytes(b64u_decode(jwk[k]), "big")

    public_numbers = rsa.RSAPublicNumbers(e=n("e"), n=n("n"))
    private_numbers = rsa.RSAPrivateNumbers(
        p=n("p"),
        q=n("q"),
        d=n("d"),
        dmp1=n("dp"),
        dmq1=n("dq"),
        iqmp=n("qi"),
        public_numbers=public_numbers,
    )
    return private_numbers.private_key()


def jwk_to_public_key(jwk: dict[str, Any]) -> rsa.RSAPublicKey:
    def n(k: str) -> int:
        return int.from_bytes(b64u_decode(jwk[k]), "big")

    return rsa.RSAPublicNumbers(e=n("e"), n=n("n")).public_key()


def public_key_from_spki_b64(spki_b64: str) -> rsa.RSAPublicKey:
    der = base64.b64decode(spki_b64)
    key = serialization.load_der_public_key(der)
    assert isinstance(key, rsa.RSAPublicKey)
    return key


def spki_b64_from_public_key(pub: rsa.RSAPublicKey) -> str:
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def device_key_id_from_spki_b64(spki_b64: str) -> str:
    return sha256_hex(base64.b64decode(spki_b64))


def sign_pss_sha256(private_key: rsa.RSAPrivateKey, data: bytes, salt_length: int = 32) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_length),
        hashes.SHA256(),
    )


def sign_device_challenge(private_key: rsa.RSAPrivateKey, device_challenge_b64: str) -> str:
    """Sign a Transmit `transmit_platform_device_validation` challenge.

    The message signed is the base64 string of the challenge AS ASCII bytes
    (not the decoded bytes). Discovered empirically via tests/probe_signed_message.py
    against the HAR capture. Algorithm: RSA-PSS, MGF1-SHA256, salt=32, hash=SHA256.

    Returns the signature as a standard base64 string (with padding).
    """
    signature = sign_pss_sha256(private_key, device_challenge_b64.encode("ascii"))
    return base64.b64encode(signature).decode("ascii")


def verify_pss_sha256(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes, salt_length: int = 32) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_length),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def jwt_decode_unverified(token: str) -> dict[str, Any]:
    header_b64, payload_b64, _sig = token.split(".")
    return {
        "header": json.loads(b64u_decode(header_b64)),
        "payload": json.loads(b64u_decode(payload_b64)),
    }
