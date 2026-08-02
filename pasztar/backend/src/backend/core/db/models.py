from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint
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


class Nonce(Base):
    __tablename__ = "nonces"
    __table_args__ = (UniqueConstraint("client_id", "nonce"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    nonce: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


Index("ix_messages_recipient_created", Message.recipient_id, Message.created_at)
Index("ix_messages_sender_created", Message.sender_id, Message.created_at)
Index("ix_nonces_created", Nonce.created_at)
