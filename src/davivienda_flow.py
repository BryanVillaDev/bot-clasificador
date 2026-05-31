"""
Orquestador end-to-end del flujo LifeMiles -> Davivienda TMA.

Pasos:
  1. POST LifeMiles instant-issuance-auth -> OTP JWT.
  2. POST auth/v1/token jwt-bearer + refresh -> access_token.
  3. Genera RSA 2048 efimero (kid=timestamp).
  4. POST workflow stepId=TMA000  body cleartext = {llavePublica, tipoOrigen, ip}.
  5. POST workflow stepId=TMA001  body cleartext = {tipoDocumento, numeroDocumento, opcionRetoma, ip}.
  6. Si la respuesta de TMA001 trae authTMAurl, lo imprime (la pantalla de apiauth.davivienda.com).

Uso:
    python src/davivienda_flow.py --cedula 79666962
    python src/davivienda_flow.py --cedula 79666962 --tipo 01 -v
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lifemiles_origin import request_otp  # noqa: E402
from workflow import init_session  # noqa: E402


def run(cedula: str, tipo: str, *, verbose: bool = False) -> dict:
    print("[1/4] solicitando OTP a lifemiles...")
    otp_data = request_otp()
    otp_jwt = otp_data["otp"]
    print(f"      OTP clientId = {otp_data['clientId']}")

    print("[2/4] init session (auth + RSA + IP + JWKS)...")
    session = init_session(otp_jwt, verbose=verbose)

    print("[3/4] callWorkflow TMA000 (registro de pubkey)...")
    tma000_payload = {
        "llavePublica": json.dumps(session.client_key.public_jwk, separators=(",", ":")),
        "tipoOrigen": "TMA",
    }
    tma000_resp = session.call_workflow("TMA000", tma000_payload)
    print(f"      next stepId = {tma000_resp['__envelope']['stepId']}")
    if verbose:
        print("      decrypted response:")
        print(json.dumps({k: v for k, v in tma000_resp.items() if k != "__envelope"}, indent=2, ensure_ascii=False))

    print(f"[4/4] callWorkflow TMA001 (envio de cedula {tipo}-{cedula})...")
    tma001_payload = {
        "tipoDocumento": tipo,
        "numeroDocumento": cedula,
        "opcionRetoma": "0",
    }
    tma001_resp = session.call_workflow("TMA001", tma001_payload)
    print(f"      next stepId = {tma001_resp['__envelope']['stepId']}")
    if verbose:
        print("      decrypted response:")
        print(json.dumps({k: v for k, v in tma001_resp.items() if k != "__envelope"}, indent=2, ensure_ascii=False))

    # Diferentes flujos usan distintos field names; cubrimos los conocidos.
    auth_url = (
        tma001_resp.get("authWidgetUrl")
        or tma001_resp.get("authTMAurl")
        or ""
    )
    if auth_url:
        print()
        print("==> EXITO -- siguiente URL OAuth para apiauth.davivienda.com:")
        print(auth_url)
        if tma001_resp.get("state"):
            print(f"    OAuth state    = {tma001_resp['state']}")
        if tma001_resp.get("verifier"):
            print(f"    PKCE verifier  = {tma001_resp['verifier']}")
            print("    (guardar para canjear el `code` al final del callback)")
        print(f"    next stepId    = {tma001_resp['__envelope']['stepId']}")
    else:
        print()
        print("==> Sin authWidgetUrl/authTMAurl. Respuesta:")
        for k, v in tma001_resp.items():
            if k != "__envelope":
                preview = str(v)[:200]
                print(f"    {k}: {preview}")
    return tma001_resp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cedula", required=True)
    ap.add_argument("--tipo", default="01", help="01=CC, 02=CE, etc.")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    run(args.cedula, args.tipo, verbose=args.verbose)


if __name__ == "__main__":
    main()
