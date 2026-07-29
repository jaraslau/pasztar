import base64
import os
import uuid
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite://")

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pasztar.app import app
from pasztar.core.db.models import Base
from pasztar.core.db.session import get_db
from pasztar.core.signing import signature_payload


engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base.metadata.create_all(bind=engine)


def db_override():
    with SessionLocal() as session:
        yield session


app.dependency_overrides[get_db] = db_override
client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    return private, base64.b64encode(public).decode()


def signed(
    method: str,
    path: str,
    body: bytes,
    client_id: str,
    private,
    timestamp: str | None = None,
    nonce: str | None = None,
):
    timestamp = timestamp or datetime.now(UTC).isoformat()
    nonce = nonce or str(uuid.uuid4())
    payload = signature_payload(method, path, timestamp, nonce, body)
    return {
        "X-Client-Id": client_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": base64.b64encode(private.sign(payload)).decode(),
    }


def test_register_send_fetch_and_replay_rejection():
    alice_private, alice_public = keypair()
    _, bob_public = keypair()

    assert client.post(
        "/clients",
        json={"id": "alice", "display_name": "Alice", "public_key": alice_public},
    ).status_code == 201
    assert client.post(
        "/clients",
        json={"id": "bob", "display_name": "Bob", "public_key": bob_public},
    ).status_code == 201

    body = b'{"id":"m1","recipient_id":"bob","ciphertext":"opaque-ciphertext"}'
    headers = signed("POST", "/messages", body, "alice", alice_private)
    sent = client.post("/messages", content=body, headers=headers)
    assert sent.status_code == 201
    assert sent.json()["ciphertext"] == "opaque-ciphertext"

    replay = client.post("/messages", content=body, headers=headers)
    assert replay.status_code == 401

    fetch_headers = signed("GET", "/messages", b"", "alice", alice_private)
    fetched = client.get("/messages", headers=fetch_headers)
    assert fetched.status_code == 200
    assert [message["id"] for message in fetched.json()] == ["m1"]


def test_auth_rejects_unknown_client_bad_signature_and_stale_timestamp():
    alice_private, alice_public = keypair()
    assert client.post(
        "/clients",
        json={"id": "alice", "display_name": "Alice", "public_key": alice_public},
    ).status_code == 201

    body = b'{"id":"m1","recipient_id":"alice","ciphertext":"opaque"}'

    unknown_headers = signed("POST", "/messages", body, "missing", alice_private)
    assert (
        client.post("/messages", content=body, headers=unknown_headers).status_code
        == 401
    )

    bad_headers = signed("POST", "/messages", body, "alice", alice_private)
    bad_headers["X-Signature"] = base64.b64encode(b"bad").decode()
    assert client.post("/messages", content=body, headers=bad_headers).status_code == 401

    stale_headers = signed(
        "POST",
        "/messages",
        body,
        "alice",
        alice_private,
        timestamp=(datetime.now(UTC) - timedelta(minutes=10)).isoformat(),
    )
    assert (
        client.post("/messages", content=body, headers=stale_headers).status_code == 401
    )


def test_duplicate_message_id_recipient_isolation_and_limit():
    alice_private, alice_public = keypair()
    bob_private, bob_public = keypair()
    charlie_private, charlie_public = keypair()
    for client_id, display_name, public_key in [
        ("alice", "Alice", alice_public),
        ("bob", "Bob", bob_public),
        ("charlie", "Charlie", charlie_public),
    ]:
        assert client.post(
            "/clients",
            json={
                "id": client_id,
                "display_name": display_name,
                "public_key": public_key,
            },
        ).status_code == 201

    for message_id in ["m1", "m2", "m3"]:
        body = (
            f'{{"id":"{message_id}","recipient_id":"bob",'
            f'"ciphertext":"opaque-{message_id}"}}'
        ).encode()
        assert client.post(
            "/messages",
            content=body,
            headers=signed("POST", "/messages", body, "alice", alice_private),
        ).status_code == 201

    duplicate = b'{"id":"m1","recipient_id":"bob","ciphertext":"again"}'
    assert client.post(
        "/messages",
        content=duplicate,
        headers=signed("POST", "/messages", duplicate, "alice", alice_private),
    ).status_code == 409

    bob_headers = signed("GET", "/messages?limit=2", b"", "bob", bob_private)
    bob_messages = client.get("/messages?limit=2", headers=bob_headers)
    assert bob_messages.status_code == 200
    assert [message["id"] for message in bob_messages.json()] == ["m1", "m2"]

    charlie_headers = signed("GET", "/messages", b"", "charlie", charlie_private)
    charlie_messages = client.get("/messages", headers=charlie_headers)
    assert charlie_messages.status_code == 200
    assert charlie_messages.json() == []
