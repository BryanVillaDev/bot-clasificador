"""Pub/sub en proceso para empujar updates de job a WebSockets y Telegram."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any


class Hub:
    def __init__(self) -> None:
        self._subs: dict[int, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, job_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subs[job_id].add(q)
        return q

    def unsubscribe(self, job_id: int, q: asyncio.Queue) -> None:
        self._subs[job_id].discard(q)
        if not self._subs[job_id]:
            self._subs.pop(job_id, None)

    def publish(self, job_id: int, event: dict[str, Any]) -> None:
        for q in list(self._subs.get(job_id, ())):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # subscriber lento; ignoramos


hub = Hub()
