"""Entrypoint unico: arranca FastAPI + worker (en startup hook) + bot Telegram.

  python -m src.main
"""
from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn

from web.config import HOST, PORT, TELEGRAM_ENABLED
from telegram_bot.bot import run_bot

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
)
log = logging.getLogger("main")


async def main() -> None:
    config = uvicorn.Config(
        "web.app:app",
        host=HOST,
        port=PORT,
        log_level="info",
        loop="asyncio",
        access_log=True,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
    server = uvicorn.Server(config)
    tasks = [asyncio.create_task(server.serve(), name="uvicorn")]
    if TELEGRAM_ENABLED:
        tasks.append(asyncio.create_task(run_bot(), name="telegram"))
    log.info("BotCasa iniciado en http://%s:%d (telegram=%s)", HOST, PORT, TELEGRAM_ENABLED)
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("bye")
