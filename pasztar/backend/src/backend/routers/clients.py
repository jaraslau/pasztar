from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.auth import require_client
from backend.core.db.models import Client, now
from backend.core.db.session import get_db
from backend.core.events import events
from backend.core.helpers.clients import existing_registration
from backend.core.signing import fingerprint
from backend.schemas.clients import (
    ClientCreate,
    ClientOut,
    ClientUpdate,
    HeartbeatOut,
)

router = APIRouter()
Db = Annotated[Session, Depends(get_db)]
CurrentClient = Annotated[Client, Depends(require_client)]


@router.post(
    "/clients",
    response_model=ClientOut,
    status_code=status.HTTP_201_CREATED,
)
def register_client(
    payload: ClientCreate,
    response: Response,
    db: Db,
) -> Client:
    if existing := db.get(Client, payload.id):
        return existing_registration(existing, payload, response)

    client = Client(
        id=payload.id,
        display_name=payload.display_name,
        public_key=payload.public_key,
        encryption_public_key=payload.encryption_public_key,
        fingerprint=fingerprint(payload.public_key),
        last_seen=now(),
    )
    db.add(client)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return existing_registration(db.get(Client, payload.id), payload, response)
    db.refresh(client)
    events.publish("clients")
    return client


@router.patch("/clients/me", response_model=ClientOut)
def update_client(
    payload: ClientUpdate,
    db: Db,
    client: CurrentClient,
) -> Client:
    if payload.id != client.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "client id mismatch")
    client.display_name = payload.display_name
    client.public_key = payload.public_key
    client.encryption_public_key = payload.encryption_public_key
    client.fingerprint = fingerprint(payload.public_key)
    client.last_seen = now()
    db.commit()
    db.refresh(client)
    events.publish("clients")
    return client


@router.get("/clients", response_model=list[ClientOut])
def list_clients(
    db: Db,
    _: CurrentClient,
) -> list[Client]:
    return list(db.scalars(select(Client).order_by(Client.display_name, Client.id)))


@router.post("/heartbeat", response_model=HeartbeatOut)
def heartbeat(
    db: Db,
    client: CurrentClient,
) -> HeartbeatOut:
    client.last_seen = now()
    db.commit()
    db.refresh(client)
    events.publish("clients")
    return HeartbeatOut(last_seen=client.last_seen)
