import asyncio
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from backend.core.auth import require_client
from backend.core.db.models import Client
from backend.core.events import events

router = APIRouter()
CurrentClient = Annotated[Client, Depends(require_client)]


@router.get("/events")
async def stream_events(
    request: Request,
    _: CurrentClient,
) -> StreamingResponse:
    async def stream() -> AsyncIterator[str]:
        async for queue in events.listen():
            yield "event: ready\ndata: {}\n\n"
            while not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=25)
                    yield f"event: {event}\ndata: {{}}\n\n"
                except TimeoutError:
                    yield ": keepalive\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")
