"""SQLAlchemy 2.0 async (MariaDB via asyncmy)."""
from __future__ import annotations

import datetime as dt
from typing import AsyncIterator

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .config import DATABASE_URL, TABLE_PREFIX


def _t(name: str) -> str:
    return f"{TABLE_PREFIX}{name}"


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = _t("users")
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Integer, default=0, nullable=False)
    telegram_chat_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())


class Job(Base):
    __tablename__ = _t("jobs")
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey(_t("users") + ".id"), nullable=True)
    telegram_chat_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending/running/done/failed/cancelled
    total: Mapped[int] = mapped_column(Integer, default=0)
    done: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    items: Mapped[list["JobItem"]] = relationship(back_populates="job", lazy="selectin")

    @property
    def progress_pct(self) -> int:
        if self.total <= 0:
            return 0
        return int(100 * (self.done + self.failed) / self.total)


class JobItem(Base):
    __tablename__ = _t("items")
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(ForeignKey(_t("jobs") + ".id"), nullable=False, index=True)
    cedula: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    tipo: Mapped[str] = mapped_column(String(4), default="01")
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending/running/done/failed
    bucket: Mapped[str | None] = mapped_column(String(32), nullable=True)
    envelope_step: Mapped[str | None] = mapped_column(String(32), nullable=True)
    message: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    classified_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    job: Mapped[Job] = relationship(back_populates="items")
    __table_args__ = (UniqueConstraint("job_id", "cedula", name="uq_job_cedula"),)


class Alert(Base):
    __tablename__ = _t("alerts")
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    level: Mapped[str] = mapped_column(String(16), default="warning")  # info/warning/error
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())
    notified: Mapped[bool] = mapped_column(Integer, default=0)


class TelegramSubscriber(Base):
    __tablename__ = _t("tg_subs")
    chat_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())


# --- engine + session ------------------------------------------------------

engine = create_async_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=1800, echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_db() -> None:
    """Crea tablas si no existen."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as s:
        yield s


# --- helpers -------------------------------------------------------------

async def reset_running_to_pending() -> int:
    """Al boot, items que quedaron en 'running' los devolvemos a pending."""
    async with SessionLocal() as s:
        from sqlalchemy import update
        res = await s.execute(
            update(JobItem).where(JobItem.status == "running").values(status="pending")
        )
        await s.commit()
        return res.rowcount or 0
