from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.core.db.models import Call, CallParticipant, CallSignal, now
from backend.core.events import events
from backend.core.settings import settings
from backend.schemas.calls import CallOut


def call_pair(first: str, second: str) -> tuple[str, str]:
    return tuple(sorted((first, second)))


def participants_for(db: Session, call_id: str) -> list[str]:
    return list(
        db.scalars(
            select(CallParticipant.client_id)
            .where(CallParticipant.call_id == call_id)
            .order_by(CallParticipant.client_id)
        )
    )


def call_out(db: Session, call: Call) -> CallOut:
    return CallOut(
        id=call.id,
        client_a_id=call.client_a_id,
        client_b_id=call.client_b_id,
        started_by_id=call.started_by_id,
        created_at=call.created_at,
        ended_at=call.ended_at,
        participants=participants_for(db, call.id),
    )


def active_call_for_pair(db: Session, first: str, second: str) -> Call | None:
    client_a_id, client_b_id = call_pair(first, second)
    return db.scalar(
        select(Call).where(
            Call.client_a_id == client_a_id,
            Call.client_b_id == client_b_id,
            Call.ended_at.is_(None),
        )
    )


def visible_active_call(db: Session, call_id: str, client_id: str) -> Call:
    call = db.get(Call, call_id)
    if (
        call is None
        or call.ended_at is not None
        or client_id not in {call.client_a_id, call.client_b_id}
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown call")
    return call


def end_empty_calls(db: Session, call_ids: set[str]) -> None:
    for call_id in call_ids:
        call = db.get(Call, call_id)
        if (
            call is not None
            and call.ended_at is None
            and not participants_for(db, call_id)
        ):
            call.ended_at = now()


def prune_stale_calls(db: Session) -> None:
    signal_cutoff = now() - timedelta(seconds=settings.call_signal_stale_after_seconds)
    pruned = db.execute(
        delete(CallSignal).where(CallSignal.created_at < signal_cutoff)
    ).rowcount
    participant_cutoff = now() - timedelta(seconds=settings.call_stale_after_seconds)
    stale = list(
        db.scalars(
            select(CallParticipant).where(
                CallParticipant.last_seen_at < participant_cutoff
            )
        )
    )
    if not stale:
        if pruned:
            db.commit()
        return
    call_ids = {participant.call_id for participant in stale}
    for participant in stale:
        db.delete(participant)
    db.flush()
    end_empty_calls(db, call_ids)
    db.commit()
    events.publish("calls")


def leave_other_calls(
    db: Session,
    client_id: str,
    keep_call_id: str | None = None,
) -> None:
    participants = list(
        db.scalars(
            select(CallParticipant)
            .join(Call, Call.id == CallParticipant.call_id)
            .where(CallParticipant.client_id == client_id, Call.ended_at.is_(None))
        )
    )
    call_ids = set()
    for participant in participants:
        if participant.call_id == keep_call_id:
            continue
        call_ids.add(participant.call_id)
        db.delete(participant)
    db.flush()
    end_empty_calls(db, call_ids)


def join_call(db: Session, call: Call, client_id: str) -> None:
    participant = db.get(CallParticipant, {"call_id": call.id, "client_id": client_id})
    if participant is None:
        db.add(
            CallParticipant(
                call_id=call.id,
                client_id=client_id,
                last_seen_at=now(),
            )
        )
    else:
        participant.last_seen_at = now()


def clear_signals_for(db: Session, call_id: str, client_id: str) -> None:
    db.execute(
        delete(CallSignal).where(
            CallSignal.call_id == call_id,
            CallSignal.recipient_id == client_id,
        )
    )
