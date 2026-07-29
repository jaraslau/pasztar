from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from pasztar.core.auth import require_client
from pasztar.core.db.models import Client, now
from pasztar.core.db.session import get_db
from pasztar.core.signing import fingerprint
from pasztar.schemas.clients import ClientCreate, ClientOut, HeartbeatOut

router = APIRouter()


@router.post("/clients", response_model=ClientOut, status_code=status.HTTP_201_CREATED)
def register_client(payload: ClientCreate, db: Session = Depends(get_db)) -> Client:
    if db.get(Client, payload.id) is not None:
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


@router.patch("/clients/me", response_model=ClientOut)
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
    return HeartbeatOut(last_seen=client.last_seen)
