from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pasztar.auth import fingerprint, require_client
from pasztar.db import get_db, init_db
from pasztar.models import Client, Message, now
from pasztar.schemas import ClientCreate, ClientOut, HeartbeatOut, MessageCreate, MessageOut


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(title="Pasztar", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/clients", response_model=ClientOut, status_code=status.HTTP_201_CREATED)
def register_client(payload: ClientCreate, db: Session = Depends(get_db)) -> Client:
    client = db.get(Client, payload.id)
    if client is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "client already exists")

    client = Client(
        id=payload.id,
        display_name=payload.display_name,
        public_key=payload.public_key,
        fingerprint=fingerprint(payload.public_key),
        last_seen=now(),
    )
    db.add(client)

    db.commit()
    db.refresh(client)
    return client


@app.patch("/clients/me", response_model=ClientOut)
def update_client(
    payload: ClientCreate,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> Client:
    if payload.id != client.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "client id mismatch")
    client.display_name = payload.display_name
    client.public_key = payload.public_key
    client.fingerprint = fingerprint(payload.public_key)
    client.last_seen = now()
    db.commit()
    db.refresh(client)
    return client


@app.get("/clients", response_model=list[ClientOut])
def list_clients(
    db: Session = Depends(get_db),
    _: Client = Depends(require_client),
) -> list[Client]:
    return list(db.scalars(select(Client).order_by(Client.display_name, Client.id)))


@app.post("/heartbeat", response_model=HeartbeatOut)
def heartbeat(
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> HeartbeatOut:
    client.last_seen = now()
    db.commit()
    db.refresh(client)
    return HeartbeatOut(last_seen=client.last_seen)


@app.post("/messages", response_model=MessageOut, status_code=status.HTTP_201_CREATED)
def create_message(
    payload: MessageCreate,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> Message:
    if db.get(Client, payload.recipient_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown recipient")

    message = Message(
        id=payload.id,
        sender_id=client.id,
        recipient_id=payload.recipient_id,
        ciphertext=payload.ciphertext,
    )
    db.add(message)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "message id already exists") from exc

    db.refresh(message)
    return message


@app.get("/messages", response_model=list[MessageOut])
def list_messages(
    since: datetime | None = None,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> list[Message]:
    stmt = select(Message).where(
        or_(Message.sender_id == client.id, Message.recipient_id == client.id)
    )
    if since is not None:
        stmt = stmt.where(Message.created_at > since)
    return list(db.scalars(stmt.order_by(Message.created_at, Message.id)))


@app.post("/messages/{message_id}/delivered", response_model=MessageOut)
def mark_delivered(
    message_id: str,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> Message:
    message = db.get(Message, message_id)
    if message is None or message.recipient_id != client.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown message")
    message.delivered_at = message.delivered_at or now()
    db.commit()
    db.refresh(message)
    return message


@app.post("/messages/{message_id}/read", response_model=MessageOut)
def mark_read(
    message_id: str,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> Message:
    message = db.get(Message, message_id)
    if message is None or message.recipient_id != client.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown message")
    message.read_at = message.read_at or now()
    db.commit()
    db.refresh(message)
    return message


def run() -> None:
    import uvicorn

    uvicorn.run("pasztar.main:app", host="0.0.0.0", port=8000)
