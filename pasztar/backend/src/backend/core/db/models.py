from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    encryption_public_key: Mapped[str | None] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class BootstrapState(Base):
    __tablename__ = "bootstrap_state"
    __table_args__ = (CheckConstraint("id = 1"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    consumed: Mapped[bool] = mapped_column(Boolean, nullable=False)


class Invitation(Base):
    __tablename__ = "invitations"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    creator_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    redeemed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    sender_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    recipient_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    reply_to_id: Mapped[str | None] = mapped_column(String(80))
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Call(Base):
    __tablename__ = "calls"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    client_a_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    client_b_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    started_by_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CallParticipant(Base):
    __tablename__ = "call_participants"

    call_id: Mapped[str] = mapped_column(
        ForeignKey("calls.id"), primary_key=True, nullable=False
    )
    client_id: Mapped[str] = mapped_column(
        ForeignKey("clients.id"), primary_key=True, nullable=False
    )
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class CallSignal(Base):
    __tablename__ = "call_signals"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    call_id: Mapped[str] = mapped_column(ForeignKey("calls.id"), nullable=False)
    sender_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    recipient_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Nonce(Base):
    __tablename__ = "nonces"
    __table_args__ = (UniqueConstraint("client_id", "nonce"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    nonce: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


Index("ix_messages_recipient_created", Message.recipient_id, Message.created_at)
Index("ix_messages_sender_created", Message.sender_id, Message.created_at)
Index("ix_calls_pair_active", Call.client_a_id, Call.client_b_id, Call.ended_at)
Index("ix_call_participants_last_seen", CallParticipant.last_seen_at)
Index(
    "ix_call_signals_recipient_created",
    CallSignal.recipient_id,
    CallSignal.created_at,
)
Index("ix_nonces_created", Nonce.created_at)
Index("ix_clients_last_seen", Client.last_seen)
