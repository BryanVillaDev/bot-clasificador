"""Pool async que consume bc_items pendientes y los clasifica.

- run_in_executor para llamar al classifier sync (httpx Client).
- asyncio.Semaphore limita concurrencia hacia Davivienda.
- Cada cedula usa una sesion HTTP nueva (sin cache) con UA rotado.
- Si N fallos consecutivos -> alerta.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import sys
import traceback
from pathlib import Path
from typing import Any

from sqlalchemy import select, update

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import update
from sqlalchemy.exc import OperationalError

from .config import ALERT_FAILURE_THRESHOLD, MAX_CONCURRENT_WORKERS
from .db import Alert, Job, JobItem, SessionLocal


async def _retry_update(coro_factory, attempts: int = 6, base_delay: float = 0.05) -> None:
    """Ejecuta una operacion de DB reintentando ante OperationalError 1020 (Galera certification).

    coro_factory: async callable sin args que hace el work (incluye commit).
    """
    import random
    for i in range(attempts):
        try:
            await coro_factory()
            return
        except OperationalError as e:
            # 1020 = Galera/WSREP certification failure
            if "1020" not in str(e) and "deadlock" not in str(e).lower():
                raise
            if i == attempts - 1:
                raise
            await asyncio.sleep(base_delay * (2 ** i) + random.random() * 0.05)
from .events import hub
from .useragents import random_ua

log = logging.getLogger("worker")


def _run_classify_sync(cedula: str, tipo: str) -> dict[str, Any]:
    """Llama classify.classify_one(). Refresca UA via DEFAULT_HEADERS de workflow."""
    from classify import classify_one
    from workflow import DEFAULT_HEADERS

    DEFAULT_HEADERS["user-agent"] = random_ua()
    return classify_one(cedula, tipo=tipo)


class WorkerPool:
    def __init__(self, max_concurrent: int = MAX_CONCURRENT_WORKERS) -> None:
        self.sem = asyncio.Semaphore(max_concurrent)
        self.queue: asyncio.Queue[int] = asyncio.Queue()
        self._consecutive_failures = 0
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task] = []

    async def enqueue_pending(self) -> int:
        """Carga al boot todos los items pending."""
        async with SessionLocal() as s:
            rows = (
                await s.execute(
                    select(JobItem.id).where(JobItem.status == "pending").order_by(JobItem.id)
                )
            ).scalars().all()
        for item_id in rows:
            await self.queue.put(item_id)
        return len(rows)

    async def submit(self, item_ids: list[int]) -> None:
        for i in item_ids:
            await self.queue.put(i)

    async def stop(self) -> None:
        self._stop.set()
        for t in self._tasks:
            t.cancel()

    async def _process_item(self, item_id: int) -> None:
        async with SessionLocal() as s:
            item = await s.get(JobItem, item_id)
            if item is None or item.status not in ("pending", "running"):
                log.warning("process_item(%d): status=%s -- skip", item_id, item.status if item else "None")
                return
            item.status = "running"
            await s.commit()
            cedula = item.cedula
            tipo = item.tipo
            job_id = item.job_id
        log.info("classify cedula=%s (item=%d)", cedula, item_id)

        hub.publish(job_id, {"type": "item_start", "item_id": item_id, "cedula": cedula})

        loop = asyncio.get_event_loop()
        result: dict[str, Any] | None = None
        error: str | None = None
        try:
            result = await loop.run_in_executor(None, _run_classify_sync, cedula, tipo)
            self._consecutive_failures = 0
        except Exception as e:
            error = f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=4)}"
            self._consecutive_failures += 1
            if self._consecutive_failures >= ALERT_FAILURE_THRESHOLD:
                await self._raise_alert(
                    "error",
                    f"Worker: {self._consecutive_failures} fallos consecutivos. "
                    f"Ultimo error en cedula {cedula}: {type(e).__name__}: {e}",
                )
                self._consecutive_failures = 0

        # Actualizar el item -- no es concurrente, cada item es procesado por un solo worker.
        async with SessionLocal() as s:
            item = await s.get(JobItem, item_id)
            if item is None:
                return
            item.classified_at = dt.datetime.utcnow()
            if result is not None:
                item.status = "done"
                item.bucket = result.get("bucket")
                item.envelope_step = result.get("envelope_stepId")
                item.message = result.get("message") or None
                item.raw_json = result
                item.error = None
            else:
                item.status = "failed"
                item.error = error
            await s.commit()
            item_status = item.status
            item_bucket = item.bucket
            item_error = item.error

        # Incrementar contadores de forma atomica con retry para Galera.
        async def _bump():
            async with SessionLocal() as s:
                if item_status == "done":
                    await s.execute(update(Job).where(Job.id == job_id).values(done=Job.done + 1))
                else:
                    await s.execute(update(Job).where(Job.id == job_id).values(failed=Job.failed + 1))
                await s.commit()
        await _retry_update(_bump)

        # Si terminamos, marcar el job done/failed.
        async def _maybe_finish():
            async with SessionLocal() as s:
                job = await s.get(Job, job_id)
                if job is None or job.done + job.failed < job.total or job.status != "running":
                    return
                await s.execute(
                    update(Job)
                    .where(Job.id == job_id, Job.status == "running")
                    .values(
                        status="done" if job.failed < job.total else "failed",
                        finished_at=dt.datetime.utcnow(),
                    )
                )
                await s.commit()
        try:
            await _retry_update(_maybe_finish)
        except Exception:
            log.exception("_maybe_finish failed")

        # publicar evento WS
        async with SessionLocal() as s:
            job = await s.get(Job, job_id)
            if job is not None:
                hub.publish(
                    job_id,
                    {
                        "type": "item_done",
                        "item_id": item_id,
                        "cedula": cedula,
                        "bucket": item_bucket,
                        "status": item_status,
                        "error": item_error,
                        "done": job.done,
                        "failed": job.failed,
                        "total": job.total,
                        "progress_pct": job.progress_pct,
                        "job_status": job.status,
                    },
                )

    async def _raise_alert(self, level: str, message: str) -> None:
        async with SessionLocal() as s:
            s.add(Alert(level=level, message=message))
            await s.commit()
        log.warning("ALERT %s: %s", level.upper(), message)

    async def _worker(self, idx: int) -> None:
        log.info("worker %d started", idx)
        while not self._stop.is_set():
            try:
                item_id = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            log.debug("worker %d picked item %d", idx, item_id)
            try:
                async with self.sem:
                    # marca el job como running (best-effort; tolera Galera conflicts)
                    async def _mark_job_running():
                        async with SessionLocal() as s:
                            it = await s.get(JobItem, item_id)
                            if it is None:
                                return
                            await s.execute(
                                update(Job)
                                .where(Job.id == it.job_id, Job.status == "pending")
                                .values(status="running", started_at=dt.datetime.utcnow())
                            )
                            await s.commit()
                    try:
                        await _retry_update(_mark_job_running)
                    except Exception:
                        log.warning("worker %d: no se pudo marcar job running (ok, otro lo hizo)", idx)
                    await self._process_item(item_id)
                    log.debug("worker %d finished item %d", idx, item_id)
            except Exception as e:
                log.exception("worker %d outer crash on item %d: %s", idx, item_id, e)

    def start(self, n: int | None = None) -> None:
        n = n or MAX_CONCURRENT_WORKERS
        for i in range(n):
            self._tasks.append(asyncio.create_task(self._worker(i)))
        log.info("WorkerPool: started %d workers (sem=%d)", n, MAX_CONCURRENT_WORKERS)


pool = WorkerPool()
