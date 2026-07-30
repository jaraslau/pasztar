import asyncio
from collections.abc import AsyncIterator


class EventHub:
    def __init__(self) -> None:
        self._queues: set[asyncio.Queue[str]] = set()

    async def listen(self) -> AsyncIterator[asyncio.Queue[str]]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=20)
        self._queues.add(queue)
        try:
            yield queue
        finally:
            self._queues.discard(queue)

    def publish(self, event: str) -> None:
        for queue in list(self._queues):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(event)


events = EventHub()
