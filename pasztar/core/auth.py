import base64
import binascii
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pasztar.core.db.models import Client, Nonce, now
from pasztar.core.db.session import get_db
from pasztar.core.settings import settings
from pasztar.core.signing import signature_payload


async def require_client(
    request: Request,
    db: Session = Depends(get_db),
    client_id: str = Header(alias="X-Client-Id"),
    timestamp: str = Header(alias="X-Timestamp"),
    nonce: str = Header(alias="X-Nonce"),
    signature: str = Header(alias="X-Signature"),
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

    db.add(Nonce(client_id=client.id, nonce=nonce))
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "replayed nonce") from exc

    return client
