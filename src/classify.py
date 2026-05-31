"""
Clasifica cedulas en buckets segun la respuesta del workflow TMA001.

Buckets observados:
  - TIENE_CUENTA       -> envelope.stepId="AUTH", trae authWidgetUrl + state + verifier.
                          El cliente tiene cuenta de banca digital. La pantalla siguiente
                          (apiauth.davivienda.com) puede pedirle CLAVE o mostrar OFERTA
                          directa segun el estado del cliente. Desde TMA001 los dos
                          casos son indistinguibles -- para saber cual aplica hay que
                          completar el flujo Transmit + OAuth (pendiente).
  - SIN_CLAVE          -> envelope.stepId="TMA00001" o message="MSG_TMA_005"
                          (cliente Davivienda pero sin clave de banca digital)
  - QUEREMOS_CONOCERTE -> envelope.stepId="TMA013" (decrypted stepId="TMA012")
                          trae userId + newAccesToken.validate=false
                          (cliente no esta en Davivienda; onboarding)
  - DESCONOCIDO        -> cualquier otra cosa; imprime detalle para investigar

Uso:
    python src/classify.py 79672391 79667000 79667015
    python src/classify.py --from-file cedulas.txt
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lifemiles_origin import request_otp  # noqa: E402
from workflow import init_session  # noqa: E402


def classify_one(cedula: str, *, tipo: str = "01", verbose: bool = False) -> dict:
    """Corre TMA000 + TMA001 y devuelve dict con bucket + detalles."""
    otp_data = request_otp()
    session = init_session(otp_data["otp"], verbose=verbose)

    # TMA000: registra pubkey
    tma000_payload = {
        "llavePublica": json.dumps(session.client_key.public_jwk, separators=(",", ":")),
        "tipoOrigen": "TMA",
    }
    session.call_workflow("TMA000", tma000_payload)

    # TMA001: envia cedula
    tma001_payload = {
        "tipoDocumento": tipo,
        "numeroDocumento": cedula,
        "opcionRetoma": "0",
    }
    resp = session.call_workflow("TMA001", tma001_payload)

    envelope = resp.get("__envelope", {})
    next_step = envelope.get("stepId", "")
    decrypted_step = resp.get("stepId", "")
    message = resp.get("message", "")

    out = {
        "cedula": cedula,
        "tipo": tipo,
        "envelope_stepId": next_step,
        "decrypted_stepId": decrypted_step,
        "message": message,
    }

    if next_step == "AUTH" and resp.get("authWidgetUrl"):
        out["bucket"] = "TIENE_CUENTA"
        out["authWidgetUrl"] = resp.get("authWidgetUrl")
        out["state"] = resp.get("state")
        out["verifier"] = resp.get("verifier")
    elif next_step == "TMA00001" or message == "MSG_TMA_005":
        out["bucket"] = "SIN_CLAVE"
        out["callbackUrl"] = resp.get("callbackUrl")
    elif next_step == "TMA013" or decrypted_step == "TMA012":
        out["bucket"] = "QUEREMOS_CONOCERTE"
        out["userId"] = resp.get("userId")
        out["newAccesToken"] = resp.get("newAccesToken")
    else:
        out["bucket"] = "DESCONOCIDO"
        # incluye todo para inspeccion
        out["full_response"] = {k: v for k, v in resp.items() if k != "__envelope"}

    return out


def print_summary(rows: list[dict]) -> None:
    print()
    print("=" * 80)
    print(f"{'cedula':<12} {'bucket':<20} {'envelope':<14} {'extra'}")
    print("-" * 80)
    for r in rows:
        extra_bits = []
        if r["bucket"] == "TIENE_CUENTA":
            extra_bits.append("authWidgetUrl=...")
        elif r["bucket"] == "SIN_CLAVE":
            extra_bits.append(f"message={r.get('message','')}")
        elif r["bucket"] == "QUEREMOS_CONOCERTE":
            uid = r.get("userId", "")
            extra_bits.append(f"userId={uid[:16]}...")
        elif r["bucket"] == "DESCONOCIDO":
            extra_bits.append(f"decryptedStep={r.get('decrypted_stepId','')}")
        extra = " ".join(extra_bits)
        print(f"{r['cedula']:<12} {r['bucket']:<20} {r['envelope_stepId']:<14} {extra}")
    print("=" * 80)
    # contadores
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["bucket"]] = counts.get(r["bucket"], 0) + 1
    for k, v in sorted(counts.items()):
        print(f"  {k}: {v}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cedulas", nargs="*", help="cedulas a clasificar")
    ap.add_argument("--from-file", type=Path, help="archivo con una cedula por linea")
    ap.add_argument("--tipo", default="01")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--json", action="store_true", help="output JSON")
    args = ap.parse_args()

    cedulas = list(args.cedulas)
    if args.from_file:
        cedulas.extend(
            line.strip()
            for line in args.from_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        )
    if not cedulas:
        ap.error("provide at least one cedula")

    rows: list[dict] = []
    for c in cedulas:
        print(f"[classify] {c} ...")
        try:
            r = classify_one(c, tipo=args.tipo, verbose=args.verbose)
        except Exception as e:
            r = {"cedula": c, "bucket": "ERROR", "envelope_stepId": "-", "message": str(e)}
        rows.append(r)
        print(f"           -> {r['bucket']}")

    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    else:
        print_summary(rows)


if __name__ == "__main__":
    main()
