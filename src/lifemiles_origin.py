"""
Paso 0 del flujo: pedir un OTP JWT a LifeMiles que arranca la sesion TMA de
Davivienda. Sin cookies, sin auth previa.

Descubierto en capture/iniciaflow.har:
    POST https://api.lifemiles.com/svc/instant-issuance-auth
    Body: {"documentNumber":"0","entityCode":"COLDAV"}
    -> {"data":{"appUrl":"...","otp":"<JWT>","clientId":"<uuid>"}}

El JWT (use:"o", product:"TMA_CO", aud:"DAV:CLOUD:AUTH") dura 30 min y se entrega
al TMA Angular cargandolo en el fragment de la appUrl:
    https://mbaas.co.davivienda.com/tma/index.html#/solicitudInicial/<JWT>

Uso:
    python src/lifemiles_origin.py
    python src/lifemiles_origin.py --document 79666962
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))

from crypto_utils import jwt_decode_unverified  # noqa: E402

LIFEMILES_ENDPOINT = "https://api.lifemiles.com/svc/instant-issuance-auth"

HEADERS_BROWSER = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9,es-US;q=0.8,es;q=0.7",
    "content-type": "application/json",
    "origin": "https://www.lifemiles.com",
    "referer": "https://www.lifemiles.com/",
    "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
    ),
}


def request_otp(document_number: str = "0", entity_code: str = "COLDAV", *, timeout: float = 15) -> dict:
    """POST a instant-issuance-auth y retorna {"appUrl", "otp", "clientId"}.

    En el HAR original LifeMiles manda documentNumber="0" (placeholder); el OTP
    no queda atado a la cedula real.
    """
    body = {"documentNumber": document_number, "entityCode": entity_code}
    with httpx.Client(http2=True, timeout=timeout, headers=HEADERS_BROWSER) as cli:
        r = cli.post(LIFEMILES_ENDPOINT, json=body)
        r.raise_for_status()
        payload = r.json()
    errors = payload.get("errors") or []
    if errors:
        raise RuntimeError(f"LifeMiles errors: {errors}")
    return payload["data"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--document", default="0", help="Suele ser '0' en el HAR")
    ap.add_argument("--entity", default="COLDAV")
    args = ap.parse_args()

    data = request_otp(args.document, args.entity)
    print("appUrl   =", data["appUrl"])
    print("clientId =", data["clientId"])
    print("otp      =", data["otp"][:80] + "...")
    print()
    decoded = jwt_decode_unverified(data["otp"])
    print("OTP JWT header :", json.dumps(decoded["header"]))
    print("OTP JWT payload:", json.dumps(decoded["payload"], indent=2))


if __name__ == "__main__":
    main()
