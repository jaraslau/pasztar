from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.core.settings import settings
from backend.routers import clients, events, health, messages


@asynccontextmanager
async def db_lifespan(app: FastAPI) -> AsyncIterator[None]:
    engine = create_engine(
        settings.database_url,
        echo=settings.debug_mode,
        pool_pre_ping=True,
    )
    app.state.session_factory = sessionmaker[Session](
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )
    try:
        yield
    finally:
        engine.dispose()


app = FastAPI(title="Pasztar", lifespan=db_lifespan, debug=settings.debug_mode)
app.include_router(health.router)
app.include_router(clients.router)
app.include_router(messages.router)
app.include_router(events.router)
