import hashlib
import secrets
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.auth import require_client
from backend.core.db.models import BootstrapState, Client, Invitation, now
from backend.core.db.session import get_db
from backend.core.events import events
from backend.core.helpers.clients import admission_error, existing_registration
from backend.core.settings import settings
from backend.core.signing import fingerprint
from backend.schemas.clients import (
    ClientCreate,
    ClientOut,
    ClientUpdate,
    HeartbeatOut,
    InvitationOut,
    RegistrationOut,
)

router = APIRouter()
Db = Annotated[Session, Depends(get_db)]
CurrentClient = Annotated[Client, Depends(require_client)]


@router.get("/registration", response_model=RegistrationOut)
def registration(db: Db, response: Response) -> RegistrationOut:
    response.headers["Cache-Control"] = "no-store"
    if not settings.trusted_identities:
        return RegistrationOut(mode="open")
    bootstrap = db.get(BootstrapState, 1)
    if bootstrap is None or bootstrap.consumed or db.scalar(select(Client.id).limit(1)):
        return RegistrationOut(mode="invitation")
    if not settings.bootstrap_token:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Server setup is incomplete: ask the operator to configure BOOTSTRAP_TOKEN.",
        )
    return RegistrationOut(mode="bootstrap")


@router.post(
    "/invitations", response_model=InvitationOut, status_code=status.HTTP_201_CREATED
)
def create_invitation(
    db: Db, client: CurrentClient, response: Response
) -> InvitationOut:
    if not settings.trusted_identities:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Registration is open; no invitation is needed.",
        )
    token = secrets.token_urlsafe(32)
    expires_at = now() + timedelta(hours=24)
    db.add(
        Invitation(
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            creator_id=client.id,
            expires_at=expires_at,
        )
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return InvitationOut(token=token, expires_at=expires_at)


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

    if error := admission_error(db, payload):
        db.rollback()
        # A concurrent request may have completed this exact registration.
        if existing := db.get(Client, payload.id):
            return existing_registration(existing, payload, response)
        raise HTTPException(status.HTTP_403_FORBIDDEN, error)

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
