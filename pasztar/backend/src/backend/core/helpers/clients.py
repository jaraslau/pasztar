import hashlib
import secrets

from fastapi import HTTPException, Response, status
from sqlalchemy import exists, update
from sqlalchemy.orm import Session

from backend.core.db.models import BootstrapState, Client, Invitation, now
from backend.core.settings import settings
from backend.schemas.clients import ClientCreate


def admission_error(db: Session, payload: ClientCreate) -> str | None:
    """Claim admission in the same transaction as client creation."""
    if not settings.trusted_identities:
        db.execute(
            update(BootstrapState)
            .where(BootstrapState.id == 1, BootstrapState.consumed.is_(False))
            .values(consumed=True)
        )
        return None

    token = (
        payload.admission_token.get_secret_value() if payload.admission_token else ""
    )
    if not token:
        return "A bootstrap or invitation token is required."

    bootstrap = settings.bootstrap_token
    if bootstrap and secrets.compare_digest(token.encode(), bootstrap.encode()):
        claimed = db.execute(
            update(BootstrapState)
            .where(
                BootstrapState.id == 1,
                BootstrapState.consumed.is_(False),
                ~exists().where(Client.id.is_not(None)),
            )
            .values(consumed=True)
        )
        if claimed.rowcount:
            return None
        return (
            "Bootstrap has already been used. Ask an existing user for an invitation."
        )

    claimed = db.execute(
        update(Invitation)
        .where(
            Invitation.token_hash == hashlib.sha256(token.encode()).hexdigest(),
            Invitation.redeemed_at.is_(None),
            Invitation.expires_at > now(),
        )
        .values(redeemed_at=now())
    )
    if claimed.rowcount:
        return None
    return "Invalid, expired, or already used invitation token."


def same_registration(client: Client, payload: ClientCreate) -> bool:
    return (
        client.display_name == payload.display_name
        and client.public_key == payload.public_key
        and client.encryption_public_key == payload.encryption_public_key
    )


def existing_registration(
    client: Client | None,
    payload: ClientCreate,
    response: Response,
) -> Client:
    if client is not None and same_registration(client, payload):
        response.status_code = status.HTTP_200_OK
        return client
    raise HTTPException(status.HTTP_409_CONFLICT, "client already exists")
