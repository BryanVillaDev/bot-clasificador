"""CLI para crear usuarios.

Uso:
    python -m src.web.cli create-user --username brayan --password secreto
    python -m src.web.cli create-user --username brayan --password secreto --admin
"""
from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select

from .auth import hash_password
from .db import SessionLocal, User, init_db


async def create_user(username: str, password: str, admin: bool) -> None:
    await init_db()
    async with SessionLocal() as s:
        existing = (await s.execute(select(User).where(User.username == username))).scalar_one_or_none()
        if existing is not None:
            existing.password_hash = hash_password(password)
            existing.is_admin = 1 if admin else 0
            await s.commit()
            print(f"updated user {username}")
            return
        u = User(username=username, password_hash=hash_password(password), is_admin=1 if admin else 0)
        s.add(u)
        await s.commit()
        print(f"created user {username} id={u.id}")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    cu = sub.add_parser("create-user")
    cu.add_argument("--username", required=True)
    cu.add_argument("--password", required=True)
    cu.add_argument("--admin", action="store_true")
    args = ap.parse_args()
    if args.cmd == "create-user":
        asyncio.run(create_user(args.username, args.password, args.admin))


if __name__ == "__main__":
    main()
