import base64
import binascii
from datetime import UTC, datetime, timedelta
from typing import Annotated

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.db.models import Client, Nonce, now
from backend.core.db.session import get_db
from backend.core.settings import settings
from backend.core.signing import signature_payload

Db = Annotated[Session, Depends(get_db)]
ClientIdHeader = Annotated[str, Header(alias="X-Client-Id")]
TimestampHeader = Annotated[str, Header(alias="X-Timestamp")]
NonceHeader = Annotated[str, Header(alias="X-Nonce")]
SignatureHeader = Annotated[str, Header(alias="X-Signature")]


async def require_client(
    request: Request,
    db: Db,
    client_id: ClientIdHeader,
    timestamp: TimestampHeader,
    nonce: NonceHeader,
    signature: SignatureHeader,
) -> Client:
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown client")

    try:
        sent_at = datetime.fromisoformat(timestamp)
        if sent_at.tzinfo is None:
            sent_at = sent_at.replace(tzinfo=UTC)
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad timestamp") from exc

    max_skew = timedelta(seconds=settings.signature_max_skew_seconds)
    if abs(now() - sent_at.astimezone(UTC)) > max_skew:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "stale timestamp")

    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(client.public_key))
        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"
        key.verify(
            base64.b64decode(signature),
            signature_payload(
                request.method,
                target,
                timestamp,
                nonce,
                await request.body(),
            ),
        )
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad signature") from exc

    db.execute(delete(Nonce).where(Nonce.created_at < now() - max_skew))
    db.add(Nonce(client_id=client.id, nonce=nonce))
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "replayed nonce") from exc

    return client
