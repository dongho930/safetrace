"""파이프라인 이벤트 버스(SSE 원천). 사전준비 단계는 인메모리, 1주차에 Redis Streams 로 교체한다.

인터페이스(publish/subscribe/replay)는 Redis Streams(XADD/XREAD, Last-Event-ID = stream id)와 동일하게 맞췄다.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import deque
from collections.abc import AsyncIterator

from safetrace.schemas import PipelineEvent

REPLAY_SIZE = 2000
SUBSCRIBER_QUEUE = 500


class EventBus:
    def __init__(self) -> None:
        self._seq = 0
        self._buffer: deque[PipelineEvent] = deque(maxlen=REPLAY_SIZE)
        self._subs: set[asyncio.Queue[PipelineEvent]] = set()

    def publish(self, event: PipelineEvent, replayable: bool = True) -> PipelineEvent:
        self._seq += 1
        event.event_id = self._seq
        if replayable:
            self._buffer.append(event)
        for q in list(self._subs):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # 느린 구독자는 끊는다(재접속 시 Last-Event-ID 로 복구).
                self._subs.discard(q)
        return event

    @contextlib.asynccontextmanager
    async def subscribe(self, last_event_id: int = 0) -> AsyncIterator[asyncio.Queue[PipelineEvent]]:
        q: asyncio.Queue[PipelineEvent] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE)
        for ev in self._buffer:
            if ev.event_id > last_event_id and q.qsize() < SUBSCRIBER_QUEUE - 50:
                q.put_nowait(ev)
        self._subs.add(q)
        try:
            yield q
        finally:
            self._subs.discard(q)

    def is_subscribed(self, q: asyncio.Queue) -> bool:
        return q in self._subs
