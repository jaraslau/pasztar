from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.auth import require_client
from backend.core.db.models import Client, Message, now
from backend.core.db.session import get_db
from backend.core.events import events
from backend.core.settings import settings
from backend.schemas.messages import MessageCreate, MessageOut

router = APIRouter()
Db = Annotated[Session, Depends(get_db)]
CurrentClient = Annotated[Client, Depends(require_client)]


@router.post(
    "/messages", response_model=MessageOut, status_code=status.HTTP_201_CREATED
)
def create_message(
    payload: MessageCreate,
    db: Db,
    client: CurrentClient,
) -> Message:
    if db.get(Client, payload.recipient_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown recipient")
    if payload.reply_to_id is not None:
        reply_to = db.get(Message, payload.reply_to_id)
        if reply_to is None or {reply_to.sender_id, reply_to.recipient_id} != {
            client.id,
            payload.recipient_id,
        }:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown reply target")

    message = Message(
        id=payload.id,
        sender_id=client.id,
        recipient_id=payload.recipient_id,
        reply_to_id=payload.reply_to_id,
        ciphertext=payload.ciphertext,
    )
    db.add(message)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "message id already exists"
        ) from exc

    db.refresh(message)
    events.publish("messages")
    return message


@router.get("/messages", response_model=list[MessageOut])
def list_messages(
    db: Db,
    client: CurrentClient,
    since: datetime | None = None,
    limit: int = Query(
        default=settings.message_list_default_limit,
        ge=1,
        le=settings.message_list_max_limit,
    ),
) -> list[Message]:
    stmt = select(Message).where(
        or_(Message.sender_id == client.id, Message.recipient_id == client.id)
    )
    if since is not None:
        stmt = stmt.where(Message.created_at > since)
    messages = list(
        db.scalars(
            stmt.order_by(Message.created_at.desc(), Message.id.desc()).limit(limit)
        )
    )
    messages.reverse()
    return messages


@router.delete("/messages/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_message(
    message_id: str,
    db: Db,
    client: CurrentClient,
) -> None:
    message = db.get(Message, message_id)
    if message is None or client.id not in {message.sender_id, message.recipient_id}:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown message")
    db.delete(message)
    db.commit()
    events.publish("messages")


@router.post("/messages/{message_id}/delivered", response_model=MessageOut)
def mark_delivered(
    message_id: str,
    db: Db,
    client: CurrentClient,
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
    db: Db,
    client: CurrentClient,
) -> Message:
    message = db.get(Message, message_id)
    if message is None or message.recipient_id != client.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown message")
    message.read_at = message.read_at or now()
    db.commit()
    db.refresh(message)
    events.publish("messages")
    return message
