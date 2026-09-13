from datetime import timedelta

import pytest
from backend.core.cleanup import cleanup_identities
from backend.core.db.models import (
    Base,
    BootstrapState,
    Call,
    CallParticipant,
    CallSignal,
    Client,
    Invitation,
    Message,
    Nonce,
    now,
)
from backend.core.settings import settings
from backend.schemas.clients import ClientOut
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker


def test_cleanup_is_atomic_and_keeps_active_history(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "identity_inactive_days", 7)
    monkeypatch.setattr(settings, "identity_cleanup_days", 90)
    engine = create_engine(f"sqlite:///{tmp_path / 'cleanup.db'}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions.begin() as db:
        db.add(BootstrapState(id=1, consumed=True))
        for client_id, age in (("active", 0), ("inactive", 8), ("expired", 91)):
            db.add(
                Client(
                    id=client_id,
                    display_name=client_id,
                    public_key="key",
                    fingerprint="fingerprint",
                    last_seen=now() - timedelta(days=age),
                )
            )
        db.flush()
        db.add_all(
            [
                Message(
                    id="keep",
                    sender_id="active",
                    recipient_id="inactive",
                    ciphertext="old active history",
                    created_at=now() - timedelta(days=100),
                ),
                Message(
                    id="remove",
                    sender_id="active",
                    recipient_id="expired",
                    ciphertext="gone",
                ),
                Call(
                    id="call",
                    client_a_id="active",
                    client_b_id="expired",
                    started_by_id="active",
                ),
                Invitation(
                    token_hash="invite",
                    creator_id="expired",
                    expires_at=now() + timedelta(days=1),
                ),
                Nonce(client_id="expired", nonce="nonce"),
            ]
        )
        db.flush()
        db.add_all(
            [
                CallParticipant(call_id="call", client_id="active"),
                CallParticipant(call_id="call", client_id="expired"),
                CallSignal(
                    id="signal",
                    call_id="call",
                    sender_id="active",
                    recipient_id="expired",
                    ciphertext="gone",
                ),
            ]
        )
        assert not ClientOut.model_validate(db.get(Client, "active")).inactive
        assert ClientOut.model_validate(db.get(Client, "inactive")).inactive

    def interrupt_delete(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("DELETE FROM clients"):
            raise RuntimeError("interrupted cleanup")

    event.listen(engine, "before_cursor_execute", interrupt_delete)
    with pytest.raises(RuntimeError, match="interrupted cleanup"):
        cleanup_identities(sessions)
    event.remove(engine, "before_cursor_execute", interrupt_delete)
    with sessions() as db:
        assert db.get(Client, "expired") is not None
        assert db.get(Message, "remove") is not None
        assert db.get(CallSignal, "signal") is not None

    assert cleanup_identities(sessions) == 1
    assert cleanup_identities(sessions) == 0
    with sessions() as db:
        assert set(db.scalars(select(Client.id))) == {"active", "inactive"}
        assert list(db.scalars(select(Message.id))) == ["keep"]
        for model in (Call, CallParticipant, CallSignal, Invitation, Nonce):
            assert db.scalar(select(model)) is None
        assert db.get(BootstrapState, 1).consumed
    engine.dispose()


def test_cleanup_obeys_batch_size_and_does_not_reopen_bootstrap(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "identity_cleanup_batch_size", 1)
    engine = create_engine(f"sqlite:///{tmp_path / 'batch.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine)
    with sessions.begin() as db:
        db.add(BootstrapState(id=1, consumed=True))
        for client_id in ("a", "b"):
            db.add(
                Client(
                    id=client_id,
                    display_name=client_id,
                    public_key="key",
                    fingerprint="fingerprint",
                    last_seen=now()
                    - timedelta(days=settings.identity_cleanup_days + 1),
                )
            )
    assert cleanup_identities(sessions) == 1
    assert cleanup_identities(sessions) == 1
    with sessions() as db:
        assert db.scalar(select(Client)) is None
        assert db.get(BootstrapState, 1).consumed
    engine.dispose()
