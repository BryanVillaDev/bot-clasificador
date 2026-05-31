"""Telegram bot (aiogram 3) para clasificar cedulas y recibir alertas."""
from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command, CommandStart
from sqlalchemy import desc, select

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web.ani import count_in_range, fetch_range, sample_range
from web.config import TELEGRAM_BOT_TOKEN
from web.db import Alert, Job, JobItem, SessionLocal, TelegramSubscriber
from web.worker import pool

log = logging.getLogger("tg")

bot = Bot(token=TELEGRAM_BOT_TOKEN) if TELEGRAM_BOT_TOKEN else None
dp = Dispatcher()

HELP = (
    "Comandos:\n"
    "/classify <cedula>           - clasifica una sola cedula\n"
    "/batch <c1,c2,...>           - lote: hasta 50 cedulas separadas por coma o espacios\n"
    "/range <min> <max> <n> [r]   - lote desde ANI: N cedulas reales en rango (r=random)\n"
    "/count <min> <max>           - cuantas cedulas reales hay en el rango\n"
    "/jobs                        - lista tus ultimos lotes\n"
    "/job <id>                    - estado de un lote\n"
    "/subscribe                   - recibir alertas si los bots fallan\n"
    "/unsubscribe                 - dejar de recibir alertas\n"
    "/help                        - este mensaje"
)


@dp.message(CommandStart())
async def cmd_start(m: types.Message) -> None:
    await m.answer(
        "BotCasa - clasificador Davivienda LifeMiles.\n\n" + HELP
    )


@dp.message(Command("help"))
async def cmd_help(m: types.Message) -> None:
    await m.answer(HELP)


def _split_cedulas(text: str) -> list[str]:
    out: list[str] = []
    for part in text.replace(",", " ").replace(";", " ").split():
        c = "".join(ch for ch in part if ch.isdigit())
        if c:
            out.append(c)
    # dedup conservando orden
    seen = set()
    dedup = []
    for c in out:
        if c not in seen:
            seen.add(c)
            dedup.append(c)
    return dedup


@dp.message(Command("classify"))
async def cmd_classify(m: types.Message) -> None:
    parts = (m.text or "").split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip().isdigit():
        await m.answer("Uso: /classify 79672391")
        return
    cedula = parts[1].strip()
    await m.answer(f"Clasificando {cedula}...")
    loop = asyncio.get_event_loop()
    from classify import classify_one

    try:
        r = await loop.run_in_executor(None, classify_one, cedula)
    except Exception as e:
        await m.answer(f"Error: {type(e).__name__}: {e}")
        return
    bucket = r.get("bucket", "?")
    extra = ""
    if bucket == "TIENE_CUENTA":
        extra = "\nDavivienda le pedira clave para mostrar oferta/no."
    elif bucket == "SIN_CLAVE":
        extra = f"\nMensaje: {r.get('message','')}"
    elif bucket == "QUEREMOS_CONOCERTE":
        extra = "\nNo es cliente Davivienda."
    await m.answer(
        f"<b>{cedula}</b>\nBucket: <b>{bucket}</b>\nstepId: {r.get('envelope_stepId','')}{extra}",
        parse_mode="HTML",
    )


@dp.message(Command("batch"))
async def cmd_batch(m: types.Message) -> None:
    parts = (m.text or "").split(maxsplit=1)
    if len(parts) < 2:
        await m.answer("Uso: /batch 79672391 79667000 79667015")
        return
    cedulas = _split_cedulas(parts[1])[:50]
    if not cedulas:
        await m.answer("No vi cedulas validas.")
        return
    chat_id = m.chat.id
    async with SessionLocal() as s:
        job = Job(telegram_chat_id=chat_id, name=f"TG batch ({len(cedulas)})", total=len(cedulas))
        s.add(job)
        await s.flush()
        items = [JobItem(job_id=job.id, cedula=c) for c in cedulas]
        s.add_all(items)
        await s.commit()
        await s.refresh(job)
        item_ids = [i.id for i in items]
    await pool.submit(item_ids)
    await m.answer(f"Lote #{job.id} encolado con {len(cedulas)} cedulas. /job {job.id} para estado.")


@dp.message(Command("count"))
async def cmd_count(m: types.Message) -> None:
    parts = (m.text or "").split()
    if len(parts) < 3:
        await m.answer("Uso: /count 79000000 80000000")
        return
    try:
        a, b = int(parts[1]), int(parts[2])
    except ValueError:
        await m.answer("Min y max deben ser numericos.")
        return
    try:
        n = await count_in_range(a, b)
    except Exception as e:
        await m.answer(f"Error consultando ANI: {e}")
        return
    await m.answer(f"<b>{n:,}</b> cedulas en rango {a:,} - {b:,}", parse_mode="HTML")


@dp.message(Command("range"))
async def cmd_range(m: types.Message) -> None:
    parts = (m.text or "").split()
    if len(parts) < 4:
        await m.answer("Uso: /range 79000000 80000000 50 [random]")
        return
    try:
        a, b, n = int(parts[1]), int(parts[2]), int(parts[3])
    except ValueError:
        await m.answer("Argumentos invalidos.")
        return
    if not (0 <= a < b) or not (1 <= n <= 500):
        await m.answer("Validacion: 0 <= min < max y 1 <= n <= 500.")
        return
    random_mode = len(parts) >= 5 and parts[4].lower().startswith("r")
    await m.answer(f"Consultando ANI ({a:,} - {b:,}, n={n}{', random' if random_mode else ''})...")
    try:
        cedulas = (
            await sample_range(a, b, n) if random_mode else await fetch_range(a, b, n)
        )
    except Exception as e:
        await m.answer(f"Error ANI: {e}")
        return
    if not cedulas:
        await m.answer("No se encontraron cedulas en ese rango.")
        return
    chat_id = m.chat.id
    async with SessionLocal() as s:
        job = Job(
            telegram_chat_id=chat_id,
            name=f"TG range {a}-{b} ({'r' if random_mode else 'a'}, {len(cedulas)})",
            total=len(cedulas),
        )
        s.add(job)
        await s.flush()
        items = [JobItem(job_id=job.id, cedula=c) for c in cedulas]
        s.add_all(items)
        await s.commit()
        await s.refresh(job)
        item_ids = [i.id for i in items]
    await pool.submit(item_ids)
    await m.answer(
        f"Lote #{job.id} encolado con {len(cedulas)} cedulas. /job {job.id} para estado."
    )


@dp.message(Command("jobs"))
async def cmd_jobs(m: types.Message) -> None:
    async with SessionLocal() as s:
        rows = (
            await s.execute(
                select(Job).where(Job.telegram_chat_id == m.chat.id).order_by(desc(Job.id)).limit(10)
            )
        ).scalars().all()
    if not rows:
        await m.answer("No tienes lotes desde Telegram.")
        return
    lines = [f"#{j.id} {j.status} {j.done+j.failed}/{j.total} ({j.progress_pct}%) {j.name}" for j in rows]
    await m.answer("\n".join(lines))


@dp.message(Command("job"))
async def cmd_job(m: types.Message) -> None:
    parts = (m.text or "").split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip().isdigit():
        await m.answer("Uso: /job 42")
        return
    jid = int(parts[1].strip())
    async with SessionLocal() as s:
        j = await s.get(Job, jid)
        if j is None:
            await m.answer("Lote no encontrado.")
            return
        items = (
            await s.execute(select(JobItem).where(JobItem.job_id == jid).order_by(JobItem.id).limit(50))
        ).scalars().all()
    head = (
        f"<b>Lote #{j.id}</b>  {j.status}  {j.done+j.failed}/{j.total} ({j.progress_pct}%)\n"
        f"OK: {j.done}  Fallos: {j.failed}\n\n"
    )
    rows = []
    for it in items:
        b = it.bucket or "-"
        rows.append(f"{it.cedula:>12}  {it.status:<8} {b}")
    msg = head + "<pre>" + "\n".join(rows) + "</pre>"
    await m.answer(msg[:4000], parse_mode="HTML")


@dp.message(Command("subscribe"))
async def cmd_subscribe(m: types.Message) -> None:
    async with SessionLocal() as s:
        sub = await s.get(TelegramSubscriber, m.chat.id)
        if sub is None:
            s.add(TelegramSubscriber(chat_id=m.chat.id))
            await s.commit()
            await m.answer("Suscrito a alertas.")
        else:
            await m.answer("Ya estabas suscrito.")


@dp.message(Command("unsubscribe"))
async def cmd_unsubscribe(m: types.Message) -> None:
    async with SessionLocal() as s:
        sub = await s.get(TelegramSubscriber, m.chat.id)
        if sub is not None:
            await s.delete(sub)
            await s.commit()
        await m.answer("Desuscrito.")


@dp.message(F.text)
async def fallback(m: types.Message) -> None:
    await m.answer("No entendi. /help para ver comandos.")


# --- alertas: dispatcher que polea bc_alerts y avisa a suscriptores -------


async def alerts_dispatcher() -> None:
    if bot is None:
        return
    last_id = 0
    async with SessionLocal() as s:
        row = (await s.execute(select(Alert.id).order_by(desc(Alert.id)).limit(1))).scalar()
        if row:
            last_id = row
    while True:
        try:
            async with SessionLocal() as s:
                new = (
                    await s.execute(
                        select(Alert).where(Alert.id > last_id).order_by(Alert.id)
                    )
                ).scalars().all()
                if new:
                    subs = (await s.execute(select(TelegramSubscriber.chat_id))).scalars().all()
                for a in new:
                    last_id = a.id
                    text = f"[{a.level.upper()}] {a.message}"
                    for chat_id in subs:
                        try:
                            await bot.send_message(chat_id, text)
                        except Exception as e:
                            log.warning("send alert to %s failed: %s", chat_id, e)
                    a.notified = 1
                if new:
                    await s.commit()
        except Exception:
            log.exception("alerts_dispatcher loop error")
        await asyncio.sleep(5)


async def run_bot() -> None:
    if bot is None:
        log.info("Telegram bot disabled (no token)")
        return
    log.info("Telegram bot starting (polling)...")
    await asyncio.gather(
        dp.start_polling(bot, handle_signals=False),
        alerts_dispatcher(),
    )
