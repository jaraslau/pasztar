import base64
import hashlib
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pasztar.db import get_db
from pasztar.models import Client, Nonce, now

MAX_SKEW = timedelta(minutes=5)


def fingerprint(public_key: str) -> str:
    return hashlib.sha256(public_key.encode()).hexdigest()


def _signature_payload(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}".encode()


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

    if abs(now() - sent_at.astimezone(UTC)) > MAX_SKEW:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "stale timestamp")

    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(client.public_key))
        body = await request.body()
        payload = _signature_payload(
            request.method,
            request.url.path,
            timestamp,
            nonce,
            body,
        )
        key.verify(base64.b64decode(signature), payload)
    except (InvalidSignature, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad signature") from exc

    db.add(Nonce(client_id=client.id, nonce=nonce))
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "replayed nonce") from exc

    return client
