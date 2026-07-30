from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pasztar.backend.core.auth import require_client
from pasztar.backend.core.db.models import Client, Message, now
from pasztar.backend.core.db.session import get_db
from pasztar.backend.core.events import events
from pasztar.backend.schemas.messages import MessageCreate, MessageOut

router = APIRouter()


@router.post("/messages", response_model=MessageOut, status_code=status.HTTP_201_CREATED)
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
    events.publish("messages")
    return message


@router.get("/messages", response_model=list[MessageOut])
def list_messages(
    since: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> list[Message]:
    stmt = select(Message).where(
        or_(Message.sender_id == client.id, Message.recipient_id == client.id)
    )
    if since is not None:
        stmt = stmt.where(Message.created_at > since)
    return list(db.scalars(stmt.order_by(Message.created_at, Message.id).limit(limit)))


@router.post("/messages/{message_id}/delivered", response_model=MessageOut)
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
    events.publish("messages")
    return message


@router.post("/messages/{message_id}/read", response_model=MessageOut)
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
    events.publish("messages")
    return message
