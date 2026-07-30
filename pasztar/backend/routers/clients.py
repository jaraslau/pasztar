from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from pasztar.backend.core.auth import require_client
from pasztar.backend.core.db.models import Client, now
from pasztar.backend.core.db.session import get_db
from pasztar.backend.core.events import events
from pasztar.backend.core.settings import settings
from pasztar.backend.core.signing import fingerprint
from pasztar.backend.core.tokens import issue_identity_token
from pasztar.backend.schemas.clients import (
    ClientCreate,
    ClientOut,
    ClientRegisterOut,
    ClientUpdate,
    HeartbeatOut,
)

router = APIRouter()


@router.post(
    "/clients",
    response_model=ClientRegisterOut,
    status_code=status.HTTP_201_CREATED,
)
def register_client(payload: ClientCreate, db: Session = Depends(get_db)) -> ClientRegisterOut:
    if db.get(Client, payload.id) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "client already exists")

    client = Client(
        id=payload.id,
        display_name=payload.display_name,
        public_key=payload.public_key,
        encryption_public_key=payload.encryption_public_key,
        fingerprint=fingerprint(payload.public_key),
        last_seen=now(),
    )
    db.add(client)
    db.commit()
    db.refresh(client)
    events.publish("clients")
    return ClientRegisterOut(
        id=client.id,
        display_name=client.display_name,
        public_key=client.public_key,
        encryption_public_key=client.encryption_public_key,
        fingerprint=client.fingerprint,
        last_seen=client.last_seen,
        identity_token=issue_identity_token(
            client.id,
            settings.registration_token_secret,
        ),
    )


@router.patch("/clients/me", response_model=ClientOut)
def update_client(
    payload: ClientUpdate,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
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
    db: Session = Depends(get_db),
    _: Client = Depends(require_client),
) -> list[Client]:
    return list(db.scalars(select(Client).order_by(Client.display_name, Client.id)))


@router.post("/heartbeat", response_model=HeartbeatOut)
def heartbeat(
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> HeartbeatOut:
    client.last_seen = now()
    db.commit()
    db.refresh(client)
    events.publish("clients")
    return HeartbeatOut(last_seen=client.last_seen)
