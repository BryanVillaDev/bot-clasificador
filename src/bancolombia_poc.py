"""POC inicial: abre la pagina con Playwright + stealth y dump el DOM relevante."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from playwright.async_api import async_playwright
from playwright_stealth import Stealth

ROOT = Path(__file__).resolve().parent.parent
URL = "https://svpersonas.apps.bancolombia.com/crear-usuario/ingresa-tus-datos"


async def explore() -> None:
    stealth = Stealth()
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            locale="es-CO",
            timezone_id="America/Bogota",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
            ),
        )
        await stealth.apply_stealth_async(context)
        page = await context.new_page()
        print(f"[*] navegando a {URL}")
        await page.goto(URL, wait_until="networkidle", timeout=60000)
        await page.wait_for_timeout(3000)
        # screenshot
        out = ROOT / "capture" / "bancolombia" / "form.png"
        out.parent.mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=str(out), full_page=True)
        print(f"[*] screenshot -> {out}")

        # dump del form: inputs, selects, buttons
        items = await page.evaluate(
            """() => {
              const out = [];
              for (const el of document.querySelectorAll('input,select,button,bds-input,bds-select,bds-button,bc-input,bc-select,bc-button')) {
                const r = {
                  tag: el.tagName.toLowerCase(),
                  id: el.id || null,
                  name: el.getAttribute('name'),
                  type: el.getAttribute('type'),
                  placeholder: el.getAttribute('placeholder'),
                  label: el.getAttribute('label') || el.getAttribute('aria-label'),
                  text: (el.innerText || '').slice(0, 60),
                  visible: el.offsetParent !== null,
                };
                out.push(r);
              }
              return out;
            }"""
        )
        print(f"[*] encontrados {len(items)} elementos de form:")
        for i, x in enumerate(items[:30]):
            print(f"  {i:2d} {x}")

        await page.wait_for_timeout(5000)
        await browser.close()


if __name__ == "__main__":
    asyncio.run(explore())
