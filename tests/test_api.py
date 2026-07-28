import base64
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pasztar.auth import _signature_payload
from pasztar.db import get_db
from pasztar.main import app
from pasztar.models import Base


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


def keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    return private, base64.b64encode(public).decode()


def signed(method: str, path: str, body: bytes, client_id: str, private):
    timestamp = datetime.now(UTC).isoformat()
    nonce = f"{client_id}-{timestamp}"
    payload = _signature_payload(method, path, timestamp, nonce, body)
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
