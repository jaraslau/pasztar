import asyncio
import logging
from datetime import timedelta

from sqlalchemy import delete, or_, select

from backend.core.db.models import (
    Call,
    CallParticipant,
    CallSignal,
    Client,
    Invitation,
    Message,
    Nonce,
    now,
)
from backend.core.events import events
from backend.core.settings import settings

logger = logging.getLogger(__name__)


def cleanup_identities(session_factory) -> int:
    cutoff = now() - timedelta(days=settings.identity_cleanup_days)
    with session_factory.begin() as db:
        # Lock candidates against authenticated activity until deletion commits.
        # ponytail: one batch per interval; raise batch size for larger nodes.
        ids = list(
            db.scalars(
                select(Client.id)
                .where(Client.last_seen < cutoff)
                .order_by(Client.last_seen, Client.id)
                .limit(settings.identity_cleanup_batch_size)
                .with_for_update(skip_locked=True)
            )
        )
        if ids:
            calls = select(Call.id).where(
                or_(
                    Call.client_a_id.in_(ids),
                    Call.client_b_id.in_(ids),
                    Call.started_by_id.in_(ids),
                )
            )
            db.execute(
                delete(CallSignal).where(
                    or_(
                        CallSignal.call_id.in_(calls),
                        CallSignal.sender_id.in_(ids),
                        CallSignal.recipient_id.in_(ids),
                    )
                )
            )
            db.execute(
                delete(CallParticipant).where(
                    or_(
                        CallParticipant.call_id.in_(calls),
                        CallParticipant.client_id.in_(ids),
                    )
                )
            )
            db.execute(delete(Call).where(Call.id.in_(calls)))
            db.execute(
                delete(Message).where(
                    or_(
                        Message.sender_id.in_(ids),
                        Message.recipient_id.in_(ids),
                    )
                )
            )
            db.execute(delete(Invitation).where(Invitation.creator_id.in_(ids)))
            db.execute(delete(Nonce).where(Nonce.client_id.in_(ids)))
            db.execute(delete(Client).where(Client.id.in_(ids)))
        db.execute(delete(Invitation).where(Invitation.expires_at < now()))
        db.execute(
            delete(Nonce).where(
                Nonce.created_at
                < now() - timedelta(seconds=2 * settings.signature_max_skew_seconds)
            )
        )
    return len(ids)


async def cleanup_loop(session_factory, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            count = await asyncio.to_thread(cleanup_identities, session_factory)
            if count:
                logger.info("Removed %s expired identities and their history", count)
                for event in ("clients", "messages", "calls"):
                    events.publish(event)
        except Exception:
            logger.exception("Identity cleanup failed; retrying at the next interval")
        try:
            await asyncio.wait_for(
                stop.wait(), timeout=settings.identity_cleanup_interval_seconds
            )
        except TimeoutError:
            pass
