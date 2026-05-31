"""
Decrypt the JWE responses of /tmw/v1/workflow using the client RSA private
key dumped from localStorage.cryptoKeyFront. Lets us see the cleartext schema
without browser introspection.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from joserfc import jwe
from joserfc.jwk import RSAKey

ALLOWED_ALGS = ["RSA-OAEP-256", "A256CBC-HS512"]

ROOT = Path(__file__).resolve().parent.parent
KEY_PATH = ROOT / "capture" / "cryptoKeyFront.json"
HAR_PATH = ROOT / "tma_load.har"


def decrypt(jwe_str: str, key: RSAKey) -> dict:
    obj = jwe.decrypt_compact(jwe_str, key, algorithms=ALLOWED_ALGS)
    return json.loads(obj.plaintext)


def main() -> None:
    jwk_dict = json.loads(KEY_PATH.read_text())
    # TMA's node-jose dump has non-standard key_ops ("wrap","verify") that joserfc rejects.
    jwk_dict.pop("key_ops", None)
    key = RSAKey.import_key(jwk_dict)
    print(f"[*] key kid={key.kid}  use={jwk_dict.get('use')}")

    har = json.loads(HAR_PATH.read_text(encoding="utf-8"))
    for i, entry in enumerate(har["log"]["entries"], 1):
        url = entry["request"]["url"]
        if "tmw/v1/workflow" not in url:
            continue
        print()
        print(f"=== HAR entry #{i} {entry['request']['method']} {url} ===")
        req_body = json.loads(entry["request"]["postData"]["text"])
        print(f"  request.stepId   = {req_body.get('stepId')}")
        print(f"  request.clientId = {req_body.get('clientId')}")

        resp_body = json.loads(entry["response"]["content"]["text"])
        jwe_str = resp_body.get("data", {}).get("payload")
        if not jwe_str:
            print("  (no encrypted payload in response)")
            continue
        try:
            cleartext = decrypt(jwe_str, key)
        except Exception as e:
            print(f"  decrypt failed: {e}")
            continue
        print(f"  response.data.stepId = {resp_body['data'].get('stepId')}")
        print(f"  response.data.status = {resp_body['data'].get('status')}")
        print("  --- decrypted response cleartext ---")
        print(json.dumps(cleartext, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
