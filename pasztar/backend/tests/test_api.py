import base64
import json
import os
import uuid
from datetime import UTC, datetime, timedelta

os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app import app
from backend.core.db.models import Base
from backend.core.db.session import get_db
from backend.core.signing import signature_payload
from backend.core.settings import settings
from backend.routers import calls as calls_router
from backend.routers import clients as clients_router
from backend.schemas.messages import MessageCreate


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


def register_client(
    client_id: str,
    display_name: str,
    public_key: str,
    encryption_public_key: str | None = None,
) -> str:
    if encryption_public_key is None:
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
    return encryption_public_key


def test_register_is_idempotent_for_same_identity(monkeypatch: pytest.MonkeyPatch):
    published = []
    monkeypatch.setattr(clients_router.events, "publish", published.append)

    _, alice_public = keypair()
    _, alice_encryption_public = keypair()
    payload = {
        "id": "alice",
        "display_name": "Alice",
        "public_key": alice_public,
        "encryption_public_key": alice_encryption_public,
    }

    response = client.post("/clients", json=payload)
    retry = client.post("/clients", json=payload)

    assert response.status_code == 201
    assert retry.status_code == 200
    assert retry.json() == response.json()
    assert "identity_token" not in response.json()
    assert published == ["clients"]


def test_register_rejects_same_id_with_different_identity_data():
    _, alice_public = keypair()
    _, alice_encryption_public = keypair()
    first = client.post(
        "/clients",
        json={
            "id": "alice",
            "display_name": "Alice",
            "public_key": alice_public,
            "encryption_public_key": alice_encryption_public,
        },
    )
    assert first.status_code == 201

    _, other_public = keypair()
    _, other_encryption_public = keypair()
    changes = [
        {"display_name": "Alicia"},
        {"public_key": other_public},
        {"encryption_public_key": other_encryption_public},
    ]
    for change in changes:
        payload = {
            "id": "alice",
            "display_name": "Alice",
            "public_key": alice_public,
            "encryption_public_key": alice_encryption_public,
            **change,
        }
        assert client.post("/clients", json=payload).status_code == 409


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


def test_message_reply_target_round_trips_and_stays_in_chat():
    alice_private, alice_public = keypair()
    _, bob_public = keypair()
    _, charlie_public = keypair()

    register_client("alice", "Alice", alice_public)
    register_client("bob", "Bob", bob_public)
    register_client("charlie", "Charlie", charlie_public)

    original = b'{"id":"m1","recipient_id":"bob","ciphertext":"opaque"}'
    assert (
        client.post(
            "/messages",
            content=original,
            headers=signed("POST", "/messages", original, "alice", alice_private),
        ).status_code
        == 201
    )

    reply = json.dumps(
        {
            "id": "m2",
            "recipient_id": "bob",
            "reply_to_id": "m1",
            "ciphertext": "opaque-reply",
        }
    ).encode()
    sent = client.post(
        "/messages",
        content=reply,
        headers=signed("POST", "/messages", reply, "alice", alice_private),
    )
    assert sent.status_code == 201
    assert sent.json()["reply_to_id"] == "m1"

    wrong_chat_reply = json.dumps(
        {
            "id": "m3",
            "recipient_id": "charlie",
            "reply_to_id": "m1",
            "ciphertext": "opaque-wrong-chat",
        }
    ).encode()
    assert (
        client.post(
            "/messages",
            content=wrong_chat_reply,
            headers=signed(
                "POST", "/messages", wrong_chat_reply, "alice", alice_private
            ),
        ).status_code
        == 404
    )


def test_call_lifecycle_reuses_active_call_and_ends_when_empty():
    alice_private, alice_public = keypair()
    bob_private, bob_public = keypair()
    register_client("alice", "Alice", alice_public)
    register_client("bob", "Bob", bob_public)

    create = json.dumps({"recipient_id": "bob"}).encode()
    started = client.post(
        "/calls",
        content=create,
        headers=signed("POST", "/calls", create, "alice", alice_private),
    )
    assert started.status_code == 201
    call = started.json()
    assert call["client_a_id"] == "alice"
    assert call["client_b_id"] == "bob"
    assert call["started_by_id"] == "alice"
    assert call["participants"] == ["alice"]

    bob_calls = client.get(
        "/calls",
        headers=signed("GET", "/calls", b"", "bob", bob_private),
    )
    assert bob_calls.status_code == 200
    assert [item["id"] for item in bob_calls.json()] == [call["id"]]

    joined = client.post(
        f"/calls/{call['id']}/join",
        headers=signed("POST", f"/calls/{call['id']}/join", b"", "bob", bob_private),
    )
    assert joined.status_code == 200
    assert joined.json()["participants"] == ["alice", "bob"]

    retry = client.post(
        "/calls",
        content=create,
        headers=signed("POST", "/calls", create, "alice", alice_private),
    )
    assert retry.status_code == 201
    assert retry.json()["id"] == call["id"]

    bob_left = client.post(
        f"/calls/{call['id']}/leave",
        headers=signed("POST", f"/calls/{call['id']}/leave", b"", "bob", bob_private),
    )
    assert bob_left.status_code == 200
    assert bob_left.json()["ended_at"] is None
    assert bob_left.json()["participants"] == ["alice"]

    alice_left = client.post(
        f"/calls/{call['id']}/leave",
        headers=signed(
            "POST", f"/calls/{call['id']}/leave", b"", "alice", alice_private
        ),
    )
    assert alice_left.status_code == 200
    assert alice_left.json()["ended_at"] is not None
    assert alice_left.json()["participants"] == []


def test_call_visibility_and_signals_are_limited_to_chat_participants():
    alice_private, alice_public = keypair()
    bob_private, bob_public = keypair()
    charlie_private, charlie_public = keypair()
    register_client("alice", "Alice", alice_public)
    register_client("bob", "Bob", bob_public)
    register_client("charlie", "Charlie", charlie_public)

    create = json.dumps({"recipient_id": "bob"}).encode()
    started = client.post(
        "/calls",
        content=create,
        headers=signed("POST", "/calls", create, "alice", alice_private),
    )
    call_id = started.json()["id"]

    assert (
        client.post(
            f"/calls/{call_id}/join",
            headers=signed(
                "POST", f"/calls/{call_id}/join", b"", "charlie", charlie_private
            ),
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/calls/{call_id}/join",
            headers=signed("POST", f"/calls/{call_id}/join", b"", "bob", bob_private),
        ).status_code
        == 200
    )

    signal = json.dumps(
        {"id": "s1", "recipient_id": "bob", "ciphertext": "opaque-signal"}
    ).encode()
    sent = client.post(
        f"/calls/{call_id}/signals",
        content=signal,
        headers=signed(
            "POST", f"/calls/{call_id}/signals", signal, "alice", alice_private
        ),
    )
    assert sent.status_code == 201

    bob_signals = client.get(
        f"/calls/{call_id}/signals",
        headers=signed("GET", f"/calls/{call_id}/signals", b"", "bob", bob_private),
    )
    assert bob_signals.status_code == 200
    assert [item["ciphertext"] for item in bob_signals.json()] == ["opaque-signal"]

    delivered = client.get(
        f"/calls/{call_id}/signals",
        headers=signed("GET", f"/calls/{call_id}/signals", b"", "bob", bob_private),
    )
    assert delivered.status_code == 200
    assert delivered.json() == []

    charlie_signals = client.get(
        f"/calls/{call_id}/signals",
        headers=signed(
            "GET", f"/calls/{call_id}/signals", b"", "charlie", charlie_private
        ),
    )
    assert charlie_signals.status_code == 404


def test_call_signal_response_survives_recipient_poll_race(
    monkeypatch: pytest.MonkeyPatch,
):
    alice_private, alice_public = keypair()
    bob_private, bob_public = keypair()
    register_client("alice", "Alice", alice_public)
    register_client("bob", "Bob", bob_public)

    create = json.dumps({"recipient_id": "bob"}).encode()
    started = client.post(
        "/calls",
        content=create,
        headers=signed("POST", "/calls", create, "alice", alice_private),
    )
    call_id = started.json()["id"]
    assert (
        client.post(
            f"/calls/{call_id}/join",
            headers=signed("POST", f"/calls/{call_id}/join", b"", "bob", bob_private),
        ).status_code
        == 200
    )

    def recipient_polls(_: str) -> None:
        client.get(
            f"/calls/{call_id}/signals",
            headers=signed("GET", f"/calls/{call_id}/signals", b"", "bob", bob_private),
        )

    monkeypatch.setattr(calls_router.events, "publish", recipient_polls)

    signal = json.dumps(
        {"id": "s1", "recipient_id": "bob", "ciphertext": "opaque-signal"}
    ).encode()
    sent = client.post(
        f"/calls/{call_id}/signals",
        content=signal,
        headers=signed(
            "POST", f"/calls/{call_id}/signals", signal, "alice", alice_private
        ),
    )

    assert sent.status_code == 201
    assert sent.json()["ciphertext"] == "opaque-signal"


def test_call_config_exposes_ice_servers(monkeypatch: pytest.MonkeyPatch):
    alice_private, alice_public = keypair()
    register_client("alice", "Alice", alice_public)
    monkeypatch.setattr(
        settings,
        "call_ice_servers",
        [{"urls": "turn:turn.example.test:3478", "username": "u"}],
    )

    response = client.get(
        "/calls/config",
        headers=signed("GET", "/calls/config", b"", "alice", alice_private),
    )

    assert response.status_code == 200
    assert response.json() == {
        "ice_servers": [{"urls": "turn:turn.example.test:3478", "username": "u"}]
    }


def test_message_ciphertext_limit_is_generous_but_bounded():
    assert settings.message_ciphertext_max_length == 160 * 1024 * 1024
    assert any(
        getattr(item, "max_length", None) == settings.message_ciphertext_max_length
        for item in MessageCreate.model_fields["ciphertext"].metadata
    )


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
    assert (
        client.post("/messages", content=body, headers=bad_headers).status_code == 401
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
        assert (
            client.post(
                "/messages",
                content=body,
                headers=signed("POST", "/messages", body, "alice", alice_private),
            ).status_code
            == 201
        )

    duplicate = b'{"id":"m1","recipient_id":"bob","ciphertext":"again"}'
    assert (
        client.post(
            "/messages",
            content=duplicate,
            headers=signed("POST", "/messages", duplicate, "alice", alice_private),
        ).status_code
        == 409
    )

    bob_headers = signed("GET", "/messages?limit=2", b"", "bob", bob_private)
    bob_messages = client.get("/messages?limit=2", headers=bob_headers)
    assert bob_messages.status_code == 200
    assert [message["id"] for message in bob_messages.json()] == ["m2", "m3"]

    charlie_headers = signed("GET", "/messages", b"", "charlie", charlie_private)
    charlie_messages = client.get("/messages", headers=charlie_headers)
    assert charlie_messages.status_code == 200
    assert charlie_messages.json() == []


def test_delete_message_by_participant_removes_it_for_both_sides():
    alice_private, alice_public = keypair()
    bob_private, bob_public = keypair()
    charlie_private, charlie_public = keypair()
    for client_id, display_name, public_key in [
        ("alice", "Alice", alice_public),
        ("bob", "Bob", bob_public),
        ("charlie", "Charlie", charlie_public),
    ]:
        register_client(client_id, display_name, public_key)

    body = b'{"id":"m1","recipient_id":"bob","ciphertext":"opaque"}'
    assert (
        client.post(
            "/messages",
            content=body,
            headers=signed("POST", "/messages", body, "alice", alice_private),
        ).status_code
        == 201
    )

    charlie_headers = signed("DELETE", "/messages/m1", b"", "charlie", charlie_private)
    assert client.delete("/messages/m1", headers=charlie_headers).status_code == 404

    bob_headers = signed("DELETE", "/messages/m1", b"", "bob", bob_private)
    assert client.delete("/messages/m1", headers=bob_headers).status_code == 204

    alice_headers = signed("GET", "/messages", b"", "alice", alice_private)
    bob_fetch_headers = signed("GET", "/messages", b"", "bob", bob_private)
    assert client.get("/messages", headers=alice_headers).json() == []
    assert client.get("/messages", headers=bob_fetch_headers).json() == []


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
