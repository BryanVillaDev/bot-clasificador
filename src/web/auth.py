"""Password hashing + session cookie."""
from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status
from itsdangerous import BadSignature, URLSafeSerializer
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import SECRET_KEY
from .db import SessionLocal, User

log = logging.getLogger("auth")
_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
_signer = URLSafeSerializer(SECRET_KEY, salt="session-v1")

COOKIE_NAME = "bc_session"


def hash_password(p: str) -> str:
    return _pwd.hash(p)


def verify_password(p: str, h: str) -> bool:
    try:
        return _pwd.verify(p, h)
    except Exception as e:
        log.error("verify_password raised: %s", e)
        return False


def make_session_cookie(user_id: int) -> str:
    return _signer.dumps({"uid": user_id})


def read_session_cookie(token: str) -> int | None:
    try:
        data = _signer.loads(token)
        return int(data["uid"])
    except (BadSignature, KeyError, ValueError, TypeError):
        return None


async def current_user(request: Request) -> User:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        log.info("current_user: no cookie -> redirect /login (path=%s)", request.url.path)
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    uid = read_session_cookie(token)
    if uid is None:
        log.warning("current_user: bad cookie signature -> redirect /login")
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    async with SessionLocal() as s:
        u = await s.get(User, uid)
        if u is None:
            log.warning("current_user: user id=%d not found -> redirect /login", uid)
            raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
        log.info("current_user: OK user=%r id=%d", u.username, uid)
        return u
