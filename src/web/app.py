"""FastAPI app: login, dashboard, upload, vista de job, WebSocket de progreso."""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
from pathlib import Path
from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select

from .ani import count_in_range, fetch_range, ping as ani_ping, sample_range
from .auth import (
    COOKIE_NAME,
    current_user,
    hash_password,
    make_session_cookie,
    verify_password,
)
from .db import Alert, Job, JobItem, SessionLocal, User, init_db, reset_running_to_pending
from .events import hub
from .worker import pool

log = logging.getLogger("web")

ROOT = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(ROOT / "templates"))

app = FastAPI(title="Bot Casita", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")


@app.on_event("startup")
async def _startup() -> None:
    await init_db()
    rec = await reset_running_to_pending()
    if rec:
        log.info("Recovered %d items from running -> pending", rec)
    n = await pool.enqueue_pending()
    log.info("Queued %d pending items at boot", n)
    pool.start()


# --- helpers --------------------------------------------------------------


def _parse_cedulas(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in text.replace(",", "\n").replace(";", "\n").splitlines():
        c = raw.strip()
        if not c or c.startswith("#"):
            continue
        # solo digitos
        c = "".join(ch for ch in c if ch.isdigit())
        if not c or c in seen:
            continue
        seen.add(c)
        out.append(c)
    return out


async def _job_or_404(job_id: int, user: User) -> Job:
    async with SessionLocal() as s:
        j = await s.get(Job, job_id)
    if j is None:
        raise HTTPException(404, "Job no encontrado")
    if j.user_id and j.user_id != user.id and not user.is_admin:
        raise HTTPException(403, "Acceso denegado")
    return j


# --- routes ---------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if request.cookies.get(COOKIE_NAME):
        return RedirectResponse("/dashboard", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return TEMPLATES.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
):
    log.info("login attempt: user=%r pw_len=%d", username, len(password))
    async with SessionLocal() as s:
        u = (await s.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if u is None:
        log.warning("login FAIL: user not found: %r", username)
        return TEMPLATES.TemplateResponse(
            request,
            "login.html",
            {"error": "Usuario o contrasena invalidos"},
            status_code=400,
        )
    ok = verify_password(password, u.password_hash)
    log.info("login verify: user=%r id=%d ok=%s hash_prefix=%s", username, u.id, ok, u.password_hash[:10])
    if not ok:
        log.warning("login FAIL: bad password for user=%r id=%d", username, u.id)
        return TEMPLATES.TemplateResponse(
            request,
            "login.html",
            {"error": "Usuario o contrasena invalidos"},
            status_code=400,
        )
    log.info("login OK: user=%r id=%d -> setting cookie + 303", username, u.id)
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie(COOKIE_NAME, make_session_cookie(u.id), httponly=True, samesite="lax")
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE_NAME)
    return resp


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: User = Depends(current_user)):
    async with SessionLocal() as s:
        rows = (
            await s.execute(
                select(Job).where(Job.user_id == user.id).order_by(desc(Job.id)).limit(50)
            )
        ).scalars().all()
        alerts = (
            await s.execute(select(Alert).order_by(desc(Alert.id)).limit(5))
        ).scalars().all()
    return TEMPLATES.TemplateResponse(
        request,
        "dashboard.html",
        {"user": user, "jobs": rows, "alerts": alerts},
    )


@app.get("/jobs/new", response_class=HTMLResponse)
async def jobs_new_get(request: Request, user: User = Depends(current_user)):
    ani_available = await ani_ping()
    return TEMPLATES.TemplateResponse(
        request,
        "new_job.html",
        {"user": user, "ani_available": ani_available},
    )


@app.get("/api/ani/count")
async def api_ani_count(
    min: int,
    max: int,
    user: User = Depends(current_user),
) -> dict:
    if min < 0 or max < min:
        raise HTTPException(400, "rango invalido")
    if max - min > 10_000_000_000:
        raise HTTPException(400, "rango demasiado grande")
    n = await count_in_range(min, max)
    return {"min": min, "max": max, "count": n}


@app.post("/jobs/new-range")
async def jobs_new_range(
    request: Request,
    name: Annotated[str, Form()] = "",
    range_min: Annotated[int, Form()] = 0,
    range_max: Annotated[int, Form()] = 0,
    limit: Annotated[int, Form()] = 100,
    mode: Annotated[str, Form()] = "asc",  # "asc" o "random"
    tipo: Annotated[str, Form()] = "01",
    user: User = Depends(current_user),
):
    if range_max <= range_min or range_min < 0:
        return TEMPLATES.TemplateResponse(
            request,
            "new_job.html",
            {
                "user": user,
                "ani_available": True,
                "error": "Rango invalido (min < max y min >= 0).",
            },
            status_code=400,
        )
    if limit < 1 or limit > 10_000:
        return TEMPLATES.TemplateResponse(
            request,
            "new_job.html",
            {
                "user": user,
                "ani_available": True,
                "error": "El limite debe estar entre 1 y 10000.",
            },
            status_code=400,
        )
    if mode == "random":
        cedulas = await sample_range(range_min, range_max, limit)
    else:
        cedulas = await fetch_range(range_min, range_max, limit, offset=0)
    if not cedulas:
        return TEMPLATES.TemplateResponse(
            request,
            "new_job.html",
            {
                "user": user,
                "ani_available": True,
                "error": "No se encontraron cedulas en el rango.",
            },
            status_code=400,
        )
    async with SessionLocal() as s:
        job = Job(
            user_id=user.id,
            name=name or f"Rango {range_min}-{range_max} ({mode}, {len(cedulas)})",
            total=len(cedulas),
        )
        s.add(job)
        await s.flush()
        items = [JobItem(job_id=job.id, cedula=c, tipo=tipo) for c in cedulas]
        s.add_all(items)
        await s.commit()
        await s.refresh(job)
        item_ids = [i.id for i in items]
    await pool.submit(item_ids)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)


@app.post("/jobs/new")
async def jobs_new_post(
    request: Request,
    name: Annotated[str, Form()] = "",
    cedulas: Annotated[str, Form()] = "",
    tipo: Annotated[str, Form()] = "01",
    user: User = Depends(current_user),
):
    parsed = _parse_cedulas(cedulas)
    if not parsed:
        return TEMPLATES.TemplateResponse(
            request,
            "new_job.html",
            {"user": user, "error": "Pega al menos una cedula valida"},
            status_code=400,
        )
    async with SessionLocal() as s:
        job = Job(user_id=user.id, name=name or f"Lote de {len(parsed)} cedulas", total=len(parsed))
        s.add(job)
        await s.flush()
        items = [JobItem(job_id=job.id, cedula=c, tipo=tipo) for c in parsed]
        s.add_all(items)
        await s.commit()
        await s.refresh(job)
        item_ids = [i.id for i in items]
    await pool.submit(item_ids)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
async def job_view(request: Request, job_id: int, user: User = Depends(current_user)):
    job = await _job_or_404(job_id, user)
    async with SessionLocal() as s:
        items = (
            await s.execute(
                select(JobItem).where(JobItem.job_id == job_id).order_by(JobItem.id)
            )
        ).scalars().all()
    return TEMPLATES.TemplateResponse(
        request, "job.html", {"user": user, "job": job, "items": items}
    )


@app.get("/jobs/{job_id}/results.csv")
async def job_csv(job_id: int, user: User = Depends(current_user)):
    await _job_or_404(job_id, user)
    async with SessionLocal() as s:
        items = (
            await s.execute(
                select(JobItem).where(JobItem.job_id == job_id).order_by(JobItem.id)
            )
        ).scalars().all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["cedula", "tipo", "status", "bucket", "envelope_step", "message", "error"])
    for it in items:
        w.writerow(
            [it.cedula, it.tipo, it.status, it.bucket or "", it.envelope_step or "", it.message or "", it.error or ""]
        )
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=job_{job_id}.csv"},
    )


@app.get("/jobs/{job_id}/results.json")
async def job_json(job_id: int, user: User = Depends(current_user)):
    job = await _job_or_404(job_id, user)
    async with SessionLocal() as s:
        items = (
            await s.execute(
                select(JobItem).where(JobItem.job_id == job_id).order_by(JobItem.id)
            )
        ).scalars().all()
    return JSONResponse(
        {
            "job": {
                "id": job.id,
                "name": job.name,
                "status": job.status,
                "total": job.total,
                "done": job.done,
                "failed": job.failed,
            },
            "items": [
                {
                    "cedula": it.cedula,
                    "status": it.status,
                    "bucket": it.bucket,
                    "envelope_step": it.envelope_step,
                    "message": it.message,
                    "error": it.error,
                    "raw": it.raw_json,
                }
                for it in items
            ],
        }
    )


# --- WebSocket de progreso -----------------------------------------------


@app.websocket("/ws/jobs/{job_id}")
async def ws_job(ws: WebSocket, job_id: int):
    token = ws.cookies.get(COOKIE_NAME)
    if not token:
        await ws.close(code=4401)
        return
    from .auth import read_session_cookie

    uid = read_session_cookie(token)
    if uid is None:
        await ws.close(code=4401)
        return
    async with SessionLocal() as s:
        job = await s.get(Job, job_id)
    if job is None:
        await ws.close(code=4404)
        return

    await ws.accept()
    q = hub.subscribe(job_id)
    try:
        # snapshot inicial
        async with SessionLocal() as s:
            j = await s.get(Job, job_id)
            await ws.send_json(
                {
                    "type": "snapshot",
                    "done": j.done,
                    "failed": j.failed,
                    "total": j.total,
                    "progress_pct": j.progress_pct,
                    "status": j.status,
                }
            )
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30.0)
                await ws.send_json(event)
            except asyncio.TimeoutError:
                await ws.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        hub.unsubscribe(job_id, q)
