"""Carga config desde .env (python-dotenv)."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(ROOT / ".env")


def _bool(v: str | None, default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


DATABASE_URL = os.environ.get("DATABASE_URL", "")
TABLE_PREFIX = os.environ.get("TABLE_PREFIX", "bc_")
ANI_DATABASE_URL = os.environ.get("ANI_DATABASE_URL", "")
ANI_TABLE = os.environ.get("ANI_TABLE", "ani_fin")
ANI_NUIP_COL = os.environ.get("ANI_NUIP_COL", "ANINuip")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-change-me")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_ENABLED = _bool(os.environ.get("TELEGRAM_ENABLED"), False)
MAX_CONCURRENT_WORKERS = int(os.environ.get("MAX_CONCURRENT_WORKERS", "3"))
ALERT_FAILURE_THRESHOLD = int(os.environ.get("ALERT_FAILURE_THRESHOLD", "5"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL no esta seteado (revisa .env)")
