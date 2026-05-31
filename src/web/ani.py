"""Acceso read-only a la DB `ani` (tabla `ani_fin`, columna `ANINuip`).

Engine separado del de la app para mantener pools y permisos aislados.
Solo SELECT.
"""
from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from .config import ANI_DATABASE_URL, ANI_NUIP_COL, ANI_TABLE

_engine = None


def _get_engine():
    global _engine
    if not ANI_DATABASE_URL:
        raise RuntimeError("ANI_DATABASE_URL no esta configurado")
    if _engine is None:
        _engine = create_async_engine(
            ANI_DATABASE_URL,
            pool_pre_ping=True,
            pool_recycle=1800,
            pool_size=4,
            max_overflow=8,
            echo=False,
        )
    return _engine


def _safe_ident(name: str) -> str:
    # Solo letras/digitos/_; previene SQL injection en identifiers.
    if not name.replace("_", "").isalnum():
        raise ValueError(f"identificador invalido: {name!r}")
    return f"`{name}`"


_TABLE = _safe_ident(ANI_TABLE)
_COL = _safe_ident(ANI_NUIP_COL)


async def count_in_range(min_v: int, max_v: int) -> int:
    eng = _get_engine()
    async with eng.connect() as c:
        r = await c.execute(
            text(f"SELECT COUNT(*) FROM {_TABLE} WHERE {_COL} BETWEEN :a AND :b"),
            {"a": int(min_v), "b": int(max_v)},
        )
        return int(r.scalar() or 0)


async def fetch_range(min_v: int, max_v: int, limit: int, offset: int = 0) -> list[str]:
    """Devuelve cedulas (como str de digitos) en el rango, en orden ascendente."""
    eng = _get_engine()
    async with eng.connect() as c:
        r = await c.execute(
            text(
                f"SELECT {_COL} FROM {_TABLE} "
                f"WHERE {_COL} BETWEEN :a AND :b "
                f"ORDER BY {_COL} "
                f"LIMIT :n OFFSET :o"
            ),
            {"a": int(min_v), "b": int(max_v), "n": int(limit), "o": int(offset)},
        )
        return [str(row[0]) for row in r]


async def sample_range(min_v: int, max_v: int, target_count: int) -> list[str]:
    """Muestreo aleatorio en el rango. Util si el rango es enorme y solo quiero N.

    Estrategia: si el rango es <= 5*target_count, hago LIMIT en el rango ordenado;
    de lo contrario uso ORDER BY RAND() con un sub-rango primero para que sea barato.
    """
    eng = _get_engine()
    total = await count_in_range(min_v, max_v)
    if total <= target_count * 5:
        return await fetch_range(min_v, max_v, target_count, 0)
    # rango muy grande -> muestra aleatoria
    async with eng.connect() as c:
        r = await c.execute(
            text(
                f"SELECT {_COL} FROM {_TABLE} "
                f"WHERE {_COL} BETWEEN :a AND :b "
                f"ORDER BY RAND() LIMIT :n"
            ),
            {"a": int(min_v), "b": int(max_v), "n": int(target_count)},
        )
        return [str(row[0]) for row in r]


async def ping() -> bool:
    try:
        eng = _get_engine()
        async with eng.connect() as c:
            await c.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
