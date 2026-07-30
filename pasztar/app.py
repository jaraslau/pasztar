from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from pasztar.core.settings import settings
from pasztar.routers import clients, health, messages

BASE_DIR = Path(__file__).resolve().parent


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
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")
