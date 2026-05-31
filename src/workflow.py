"""
Cliente Python para el TMA workflow de Davivienda (/tmw/v1/workflow).

Replica lo que hace `cripto.encrypter` + `cripto.unencrypter` + `auth.authenticate`
del bundle TMA Angular, observado en capture/tma_main.js:

 - Genera un keypair RSA 2048 efimero por sesion, con `kid = floor(now()/1000)`.
 - Cifra el cleartext con la pub "enc" de Davivienda (kid=1131014911 del JWKS),
   alg=RSA-OAEP-256, enc=A256CBC-HS512.
 - El cliente embebe su propia pub dentro del cleartext de TMA000:
       `llavePublica = JSON.stringify(pubJwk)`
 - La respuesta viene cifrada con la pub del cliente; descifra con su privkey.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwe
from joserfc.jwk import RSAKey

from crypto_utils import b64u_encode

# --- endpoints (capture/tma_main.js -> environment object) -----------------
AUTH_URL = "https://mbaas.co.davivienda.com/auth/v1/token"
WORKFLOW_URL = "https://mbaas.co.davivienda.com/tmw/v1/workflow"
JWKS_URL = "https://mbaas.co.davivienda.com/auth/v1/keystore/.well-known/jwks.json"
GET_IP_URL = "https://mbaas.co.davivienda.com/utils/get-ip"

ALG_RSA_OAEP_256 = "RSA-OAEP-256"
ALG_A256CBC_HS512 = "A256CBC-HS512"
ALLOWED_JWE_ALGS = [ALG_RSA_OAEP_256, ALG_A256CBC_HS512]

DEFAULT_HEADERS = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "en-US,en;q=0.9",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "content-type": "application/json",
    "origin": "https://mbaas.co.davivienda.com",
    "referer": "https://mbaas.co.davivienda.com/tma/index.html",
    "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
    ),
}


# --- key + state ------------------------------------------------------------


@dataclass
class ClientKey:
    """RSA keypair efimero del cliente (lo que node-jose llama generalkeyFrontend)."""

    private_key: rsa.RSAPrivateKey
    kid: str
    public_jwk: dict[str, Any] = field(default_factory=dict)
    private_jwk: dict[str, Any] = field(default_factory=dict)


def generate_client_key() -> ClientKey:
    """Genera RSA 2048 con kid=timestamp seconds (igual que keyCreator)."""
    kid = str(int(time.time()))
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_numbers = priv.public_key().public_numbers()
    n_b = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")
    e_b = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")
    public_jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "enc",
        "alg": ALG_RSA_OAEP_256,
        "e": b64u_encode(e_b),
        "n": b64u_encode(n_b),
    }
    priv_numbers = priv.private_numbers()

    def _enc(x: int) -> str:
        return b64u_encode(x.to_bytes((x.bit_length() + 7) // 8, "big"))

    private_jwk = {
        **public_jwk,
        "d": _enc(priv_numbers.d),
        "p": _enc(priv_numbers.p),
        "q": _enc(priv_numbers.q),
        "dp": _enc(priv_numbers.dmp1),
        "dq": _enc(priv_numbers.dmq1),
        "qi": _enc(priv_numbers.iqmp),
    }
    return ClientKey(private_key=priv, kid=kid, public_jwk=public_jwk, private_jwk=private_jwk)


# --- HTTP helpers ----------------------------------------------------------


def fetch_davivienda_enc_jwk(client: httpx.Client) -> dict[str, Any]:
    """GET jwks.json -> devuelve la key con use=enc (RSA-OAEP-256)."""
    r = client.get(JWKS_URL)
    r.raise_for_status()
    for k in r.json()["keys"]:
        if k.get("use") == "enc":
            return k
    raise RuntimeError("No 'enc' key in JWKS")


def get_ip(client: httpx.Client) -> str:
    r = client.get(GET_IP_URL)
    r.raise_for_status()
    return r.json()["ip"]


def exchange_otp(client: httpx.Client, otp_jwt: str) -> dict[str, Any]:
    """OTP -> {access_token, refresh_token, token_type:bearer}."""
    body = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": otp_jwt,
    }
    r = client.post(AUTH_URL, json=body)
    r.raise_for_status()
    return r.json()


def refresh_access(client: httpx.Client, refresh_token: str, access_token: str) -> dict[str, Any]:
    body = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    headers = {"Authorization": f"Bearer {access_token}"}
    r = client.post(AUTH_URL, json=body, headers=headers)
    r.raise_for_status()
    return r.json()


# --- JWE primitives --------------------------------------------------------


def _to_rsa_key(jwk_dict: dict[str, Any]) -> RSAKey:
    """node-jose mete key_ops no estandar ('wrap','verify'); strip antes de importar."""
    cleaned = {k: v for k, v in jwk_dict.items() if k != "key_ops"}
    return RSAKey.import_key(cleaned)


def jwe_encrypt_to_pub(payload_obj: dict[str, Any], davivienda_pub_jwk: dict[str, Any]) -> str:
    """Cifra obj JSON como JWE compact a la pub de Davivienda."""
    pub = _to_rsa_key(davivienda_pub_jwk)
    protected = {
        "enc": ALG_A256CBC_HS512,
        "kid": davivienda_pub_jwk["kid"],
        "alg": ALG_RSA_OAEP_256,
    }
    plaintext = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    return jwe.encrypt_compact(protected, plaintext, pub, algorithms=ALLOWED_JWE_ALGS)


def jwe_decrypt_with_priv(jwe_str: str, client_key: ClientKey) -> dict[str, Any]:
    """Descifra JWE compact recibido del server con la privkey del cliente."""
    priv = _to_rsa_key(client_key.private_jwk)
    obj = jwe.decrypt_compact(jwe_str, priv, algorithms=ALLOWED_JWE_ALGS)
    return json.loads(obj.plaintext)


# --- session orchestration ------------------------------------------------


@dataclass
class WorkflowSession:
    http: httpx.Client
    client_id: str
    access_token: str
    refresh_token: str
    client_key: ClientKey
    davv_pub_jwk: dict[str, Any]
    ip: str
    verbose: bool = False

    def _log(self, *a: Any) -> None:
        if self.verbose:
            print(*a)

    def call_workflow(self, step_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Envuelve callWorkflow del bundle: agrega ip, cifra, postea, descifra."""
        full_payload = dict(payload)
        full_payload["ip"] = self.ip
        self._log(f"[workflow] -> {step_id}  cleartext={full_payload}")
        encrypted = jwe_encrypt_to_pub(full_payload, self.davv_pub_jwk)
        body = {"stepId": step_id, "payload": encrypted, "clientId": self.client_id}
        headers = {"Authorization": f"Bearer {self.access_token}"}
        r = self.http.post(WORKFLOW_URL, json=body, headers=headers)
        if r.status_code != 200:
            raise RuntimeError(f"workflow {step_id} status={r.status_code} body={r.text[:500]}")
        envelope = r.json()
        if envelope.get("errors"):
            raise RuntimeError(f"workflow {step_id} errors={envelope['errors']}")
        data = envelope["data"]
        decrypted = jwe_decrypt_with_priv(data["payload"], self.client_key)
        decrypted["__envelope"] = {
            "status": data.get("status"),
            "stepId": data.get("stepId"),
            "clientId": data.get("clientId"),
        }
        # mantiene contrato con el bundle: si la respuesta trae newAccesToken.otp,
        # podriamos re-auth (no implementado todavia, no observado).
        self._log(f"[workflow] <- {step_id}  next={data.get('stepId')} status={data.get('status')}")
        if "newAccesToken" in decrypted and decrypted["newAccesToken"].get("validate"):
            self._log("[workflow] respuesta trae newAccesToken.validate -- re-auth no implementado")
        return decrypted


def init_session(otp_jwt: str, *, verbose: bool = False) -> WorkflowSession:
    """OTP -> tokens -> RSA -> IP -> JWKS, todo en una sola sesion HTTP/2."""
    http = httpx.Client(http2=True, timeout=30, headers=DEFAULT_HEADERS)
    try:
        tokens = exchange_otp(http, otp_jwt)
        access = tokens["access_token"]
        refresh = tokens["refresh_token"]
        # el bundle hace refresh inmediato despues del jwt-bearer; copiamos
        refreshed = refresh_access(http, refresh, access)
        access = refreshed["access_token"]
        davv_pub = fetch_davivienda_enc_jwk(http)
        client_key = generate_client_key()
        ip = get_ip(http)
        # clientId = sub del OTP (es el mismo que vuelve en cada workflow response)
        from crypto_utils import jwt_decode_unverified

        client_id = jwt_decode_unverified(otp_jwt)["payload"]["sub"]
        if verbose:
            print(f"[init] clientId  = {client_id}")
            print(f"[init] access exp= {jwt_decode_unverified(access)['payload']['exp']}")
            print(f"[init] davv kid  = {davv_pub['kid']}")
            print(f"[init] client kid= {client_key.kid}")
            print(f"[init] ip        = {ip}")
        return WorkflowSession(
            http=http,
            client_id=client_id,
            access_token=access,
            refresh_token=refresh,
            client_key=client_key,
            davv_pub_jwk=davv_pub,
            ip=ip,
            verbose=verbose,
        )
    except Exception:
        http.close()
        raise
