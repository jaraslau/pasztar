import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier

import pytest
import test_api as api
from alembic import command
from alembic.config import Config
from backend.core.db.models import Base, BootstrapState, Client, Invitation, now
from backend.core.db.session import get_db
from backend.core.settings import settings
from backend.routers import clients as clients_router
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


@pytest.fixture(autouse=True)
def admission_db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'admission.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    with sessions() as db:
        db.add(BootstrapState(id=1, consumed=False))
        db.commit()

    def get_session():
        with sessions() as db:
            yield db

    monkeypatch.setitem(api.app.dependency_overrides, get_db, get_session)
    monkeypatch.setattr(settings, "trusted_identities", True)
    monkeypatch.setattr(settings, "bootstrap_token", "bootstrap-secret")
    yield sessions
    engine.dispose()


def identity(client_id, token=None):
    private, public = api.keypair()
    encryption = api.encryption_key()
    return private, {
        "id": client_id,
        "display_name": client_id,
        "public_key": public,
        "encryption_public_key": encryption,
        "admission_token": token,
    }


def bootstrap():
    private, payload = identity("alice", "bootstrap-secret")
    assert api.client.post("/clients", json=payload).status_code == 201
    return private


def invite(private, client_id="alice"):
    response = api.client.post(
        "/invitations",
        headers=api.signed("POST", "/invitations", b"", client_id, private),
    )
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    return response.json()["token"]


def test_bootstrap_and_idempotent_retry(admission_db, monkeypatch):
    assert api.client.get("/registration").json() == {"mode": "bootstrap"}
    for token in (None, "wrong", "☃"):
        _, payload = identity("alice", token)
        assert api.client.post("/clients", json=payload).status_code == 403

    _, payload = identity("alice", "bootstrap-secret")
    result = api.client.post("/clients", json=payload)
    assert result.status_code == 201
    assert "admission_token" not in result.json()
    assert api.client.get("/registration").json() == {"mode": "invitation"}
    for token in ("bootstrap-secret", None):
        assert (
            api.client.post(
                "/clients", json={**payload, "admission_token": token}
            ).status_code
            == 200
        )
    assert (
        api.client.post(
            "/clients", json={**payload, "display_name": "Other"}
        ).status_code
        == 409
    )

    # Persisted consumption survives a new session and token rotation.
    monkeypatch.setattr(settings, "bootstrap_token", "rotated")
    _, another = identity("bob", "rotated")
    assert api.client.post("/clients", json=another).status_code == 403
    with admission_db() as db:
        assert db.get(BootstrapState, 1).consumed


def test_missing_bootstrap_configuration(monkeypatch):
    monkeypatch.setattr(settings, "bootstrap_token", None)
    response = api.client.get("/registration")
    assert response.status_code == 503
    assert "BOOTSTRAP_TOKEN" in response.json()["detail"]
    _, payload = identity("alice", "anything")
    assert api.client.post("/clients", json=payload).status_code == 403


def test_invitation_auth_expiry_redemption_and_onward_inviting(admission_db):
    alice = bootstrap()
    assert api.client.post("/invitations").status_code == 422
    assert (
        api.client.post(
            "/invitations",
            headers=api.signed("POST", "/invitations", b"", "unknown", alice),
        ).status_code
        == 401
    )
    wrong_private, _ = api.keypair()
    assert (
        api.client.post(
            "/invitations",
            headers=api.signed("POST", "/invitations", b"", "alice", wrong_private),
        ).status_code
        == 401
    )

    token = invite(alice)
    with admission_db() as db:
        row = db.get(Invitation, hashlib.sha256(token.encode()).hexdigest())
        assert row.creator_id == "alice"
        assert row.redeemed_at is None
        assert (
            abs(
                (row.expires_at.replace(tzinfo=now().tzinfo) - now()).total_seconds()
                - 86400
            )
            < 10
        )
    bob, payload = identity("bob", token)
    assert api.client.post("/clients", json=payload).status_code == 201
    assert api.client.post("/clients", json=payload).status_code == 200
    _, reused = identity("mallory", token)
    assert api.client.post("/clients", json=reused).status_code == 403
    assert invite(bob, "bob") != token

    expired = invite(alice)
    with admission_db() as db:
        db.get(Invitation, hashlib.sha256(expired.encode()).hexdigest()).expires_at = (
            now() - timedelta(seconds=1)
        )
        db.commit()
    _, payload = identity("carol", expired)
    assert api.client.post("/clients", json=payload).status_code == 403


def test_conflict_does_not_consume_invitation(admission_db):
    token = invite(bootstrap())
    _, conflicting = identity("alice", token)
    assert api.client.post("/clients", json=conflicting).status_code == 409
    _, valid = identity("bob", token)
    assert api.client.post("/clients", json=valid).status_code == 201


@pytest.mark.parametrize("token_kind", ["bootstrap", "invitation"])
def test_failed_insert_rolls_back_admission(admission_db, monkeypatch, token_kind):
    token = "bootstrap-secret" if token_kind == "bootstrap" else invite(bootstrap())
    original = clients_router.fingerprint

    def fail_after_claim(_):
        raise RuntimeError("simulate interrupted registration")

    monkeypatch.setattr(clients_router, "fingerprint", fail_after_claim)
    _, payload = identity("bob", token)
    with pytest.raises(RuntimeError, match="interrupted registration"):
        api.client.post("/clients", json=payload)
    monkeypatch.setattr(clients_router, "fingerprint", original)
    assert api.client.post("/clients", json=payload).status_code == 201


@pytest.mark.parametrize("token_kind", ["bootstrap", "invitation"])
@pytest.mark.parametrize("same_identity", [False, True])
def test_concurrent_redemption(admission_db, monkeypatch, token_kind, same_identity):
    token = "bootstrap-secret" if token_kind == "bootstrap" else invite(bootstrap())
    _, first = identity("bob", token)
    _, second = identity("carol", token)
    if same_identity:
        second = first
    barrier = Barrier(2)
    original = clients_router.admission_error

    def simultaneous_claim(db, payload):
        barrier.wait(timeout=10)
        return original(db, payload)

    monkeypatch.setattr(clients_router, "admission_error", simultaneous_claim)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda payload: api.client.post("/clients", json=payload),
                [first, second],
            )
        )
    assert sorted(response.status_code for response in responses) == (
        [200, 201] if same_identity else [201, 403]
    )
    with admission_db() as db:
        assert len(list(db.scalars(select(Client)))) == (
            1 if token_kind == "bootstrap" else 2
        )


def test_concurrent_id_conflict_preserves_losing_invitation(admission_db, monkeypatch):
    alice = bootstrap()
    tokens = [invite(alice), invite(alice)]
    payloads = [identity("bob", token)[1] for token in tokens]
    barrier = Barrier(2)
    original = clients_router.admission_error

    def simultaneous_claim(db, payload):
        barrier.wait(timeout=10)
        return original(db, payload)

    monkeypatch.setattr(clients_router, "admission_error", simultaneous_claim)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda payload: api.client.post("/clients", json=payload), payloads
            )
        )
    codes = [response.status_code for response in responses]
    assert sorted(codes) == [201, 409]
    monkeypatch.setattr(clients_router, "admission_error", original)
    _, payload = identity("carol", tokens[codes.index(409)])
    assert api.client.post("/clients", json=payload).status_code == 201


def test_existing_users_and_open_registration(monkeypatch):
    monkeypatch.setattr(settings, "trusted_identities", False)
    assert api.client.get("/registration").json() == {"mode": "open"}
    alice, payload = identity("alice")
    assert api.client.post("/clients", json=payload).status_code == 201
    assert (
        api.client.post(
            "/invitations",
            headers=api.signed("POST", "/invitations", b"", "alice", alice),
        ).status_code
        == 400
    )
    monkeypatch.setattr(settings, "trusted_identities", True)
    assert api.client.get("/registration").json() == {"mode": "invitation"}
    assert (
        api.client.get(
            "/clients", headers=api.signed("GET", "/clients", b"", "alice", alice)
        ).status_code
        == 200
    )
    assert invite(alice)
    _, payload = identity("bob", "bootstrap-secret")
    assert api.client.post("/clients", json=payload).status_code == 403


@pytest.mark.parametrize("existing_user", [False, True])
def test_migration_initializes_bootstrap(tmp_path, monkeypatch, existing_user):
    database_url = f"sqlite:///{tmp_path / 'migration.db'}"
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "20260802_0004")
    engine = create_engine(database_url)
    if existing_user:
        with engine.begin() as conn:
            conn.execute(
                Client.__table__.insert().values(
                    id="legacy",
                    display_name="Legacy",
                    public_key="key",
                    encryption_public_key="key",
                    fingerprint="fingerprint",
                )
            )
    command.upgrade(config, "head")
    with engine.connect() as conn:
        assert conn.scalar(select(BootstrapState.consumed)) is existing_user
    command.downgrade(config, "20260802_0004")
    command.upgrade(config, "head")
    engine.dispose()
