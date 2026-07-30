import base64
import os
import uuid
from datetime import UTC, datetime, timedelta

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["REGISTRATION_TOKEN_SECRET"] = "test-secret"

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pasztar.backend.app import app
from pasztar.backend.core.db.models import Base
from pasztar.backend.core.db.session import get_db
from pasztar.backend.core.signing import signature_payload
from pasztar.backend.core.tokens import issue_identity_token
from pasztar.backend.routers import clients as clients_router


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


def register_client(client_id: str, display_name: str, public_key: str) -> str:
    _, encryption_public_key = keypair()
    response = client.post(
        "/clients",
        json={
            "id": client_id,
            "display_name": display_name,
            "public_key": public_key,
            "encryption_public_key": encryption_public_key,
        },
    )
    assert response.status_code == 201
    assert response.json()["encryption_public_key"] == encryption_public_key
    assert response.json()["identity_token"] == issue_identity_token(
        client_id,
        "test-secret",
    )
    return encryption_public_key


def test_register_assigns_identity_token():
    _, alice_public = keypair()
    response = client.post(
        "/clients",
        json={
            "id": "alice",
            "display_name": "Alice",
            "public_key": alice_public,
            "encryption_public_key": alice_public,
        },
    )

    assert response.status_code == 201
    assert response.json()["identity_token"] == issue_identity_token(
        "alice",
        "test-secret",
    )


def test_register_and_message_publish_events(monkeypatch: pytest.MonkeyPatch):
    published = []
    monkeypatch.setattr(clients_router.events, "publish", published.append)

    alice_private, alice_public = keypair()
    _, bob_public = keypair()
    register_client("alice", "Alice", alice_public)
    register_client("bob", "Bob", bob_public)

    body = b'{"id":"m1","recipient_id":"bob","ciphertext":"opaque"}'
    response = client.post(
        "/messages",
        content=body,
        headers=signed("POST", "/messages", body, "alice", alice_private),
    )

    assert response.status_code == 201
    assert published == ["clients", "clients", "messages"]


def signed(
    method: str,
    path: str,
    body: bytes,
    client_id: str,
    private,
    timestamp: str | None = None,
    nonce: str | None = None,
    identity_token: str | None = None,
):
    timestamp = timestamp or datetime.now(UTC).isoformat()
    nonce = nonce or str(uuid.uuid4())
    payload = signature_payload(method, path, timestamp, nonce, body)
    return {
        "X-Client-Id": client_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": base64.b64encode(private.sign(payload)).decode(),
        "X-Identity-Token": identity_token
        or issue_identity_token(client_id, "test-secret"),
    }


def test_register_send_fetch_and_replay_rejection():
    alice_private, alice_public = keypair()
    _, bob_public = keypair()

    register_client("alice", "Alice", alice_public)
    register_client("bob", "Bob", bob_public)

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
    register_client("alice", "Alice", alice_public)

    body = b'{"id":"m1","recipient_id":"alice","ciphertext":"opaque"}'

    unknown_headers = signed("POST", "/messages", body, "missing", alice_private)
    assert (
        client.post("/messages", content=body, headers=unknown_headers).status_code
        == 401
    )

    bad_headers = signed("POST", "/messages", body, "alice", alice_private)
    bad_headers["X-Signature"] = base64.b64encode(b"bad").decode()
    assert client.post("/messages", content=body, headers=bad_headers).status_code == 401

    bad_token_headers = signed(
        "POST",
        "/messages",
        body,
        "alice",
        alice_private,
        identity_token=issue_identity_token("bob", "test-secret"),
    )
    assert (
        client.post("/messages", content=body, headers=bad_token_headers).status_code
        == 401
    )

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
        register_client(client_id, display_name, public_key)

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


def test_client_directory_exposes_encryption_keys():
    alice_private, alice_public = keypair()
    bob_private, bob_public = keypair()
    alice_encryption_public = register_client("alice", "Alice", alice_public)
    bob_encryption_public = register_client("bob", "Bob", bob_public)

    headers = signed("GET", "/clients", b"", "alice", alice_private)
    response = client.get("/clients", headers=headers)

    assert response.status_code == 200
    clients = {item["id"]: item for item in response.json()}
    assert clients["alice"]["encryption_public_key"] == alice_encryption_public
    assert clients["bob"]["encryption_public_key"] == bob_encryption_public
    assert "private" not in str(response.json()).lower()
