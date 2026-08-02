from datetime import timedelta
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import and_, delete, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.auth import require_client
from backend.core.db.models import Call, CallParticipant, CallSignal, Client, now
from backend.core.db.session import get_db
from backend.core.events import events
from backend.schemas.calls import CallCreate, CallOut, CallSignalCreate, CallSignalOut

router = APIRouter()
CALL_STALE_AFTER = timedelta(seconds=45)


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
    stale = list(
        db.scalars(
            select(CallParticipant).where(
                CallParticipant.last_seen_at < now() - CALL_STALE_AFTER
            )
        )
    )
    if not stale:
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


@router.post("/calls", response_model=CallOut, status_code=status.HTTP_201_CREATED)
def create_call(
    payload: CallCreate,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> CallOut:
    prune_stale_calls(db)
    if payload.recipient_id == client.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot call yourself")
    if db.get(Client, payload.recipient_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown recipient")

    call = active_call_for_pair(db, client.id, payload.recipient_id)
    if call is None:
        client_a_id, client_b_id = call_pair(client.id, payload.recipient_id)
        call = Call(
            id=str(uuid4()),
            client_a_id=client_a_id,
            client_b_id=client_b_id,
            started_by_id=client.id,
        )
        db.add(call)
    leave_other_calls(db, client.id, keep_call_id=call.id)
    join_call(db, call, client.id)
    clear_signals_for(db, call.id, client.id)
    db.commit()
    db.refresh(call)
    events.publish("calls")
    return call_out(db, call)


@router.get("/calls", response_model=list[CallOut])
def list_calls(
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> list[CallOut]:
    prune_stale_calls(db)
    calls = list(
        db.scalars(
            select(Call)
            .where(
                Call.ended_at.is_(None),
                or_(Call.client_a_id == client.id, Call.client_b_id == client.id),
            )
            .order_by(Call.created_at, Call.id)
        )
    )
    return [call_out(db, call) for call in calls]


@router.post("/calls/{call_id}/join", response_model=CallOut)
def join(
    call_id: str,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> CallOut:
    prune_stale_calls(db)
    call = visible_active_call(db, call_id, client.id)
    leave_other_calls(db, client.id, keep_call_id=call.id)
    join_call(db, call, client.id)
    clear_signals_for(db, call.id, client.id)
    db.commit()
    db.refresh(call)
    events.publish("calls")
    return call_out(db, call)


@router.post("/calls/{call_id}/leave", response_model=CallOut)
def leave(
    call_id: str,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> CallOut:
    prune_stale_calls(db)
    call = visible_active_call(db, call_id, client.id)
    participant = db.get(CallParticipant, {"call_id": call.id, "client_id": client.id})
    if participant is not None:
        db.delete(participant)
        db.flush()
    end_empty_calls(db, {call.id})
    db.commit()
    db.refresh(call)
    events.publish("calls")
    return call_out(db, call)


@router.post("/calls/{call_id}/heartbeat", response_model=CallOut)
def heartbeat(
    call_id: str,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> CallOut:
    prune_stale_calls(db)
    call = visible_active_call(db, call_id, client.id)
    participant = db.get(CallParticipant, {"call_id": call.id, "client_id": client.id})
    if participant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not in call")
    participant.last_seen_at = now()
    db.commit()
    db.refresh(call)
    return call_out(db, call)


@router.post(
    "/calls/{call_id}/signals",
    response_model=CallSignalOut,
    status_code=status.HTTP_201_CREATED,
)
def create_signal(
    call_id: str,
    payload: CallSignalCreate,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> CallSignal:
    call = visible_active_call(db, call_id, client.id)
    if db.get(CallParticipant, {"call_id": call.id, "client_id": client.id}) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not in call")
    if payload.recipient_id not in {call.client_a_id, call.client_b_id}:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown recipient")
    if payload.recipient_id == client.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot signal yourself")
    if (
        db.get(
            CallParticipant,
            {"call_id": call.id, "client_id": payload.recipient_id},
        )
        is None
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "recipient not in call")
    signal = CallSignal(
        id=payload.id,
        call_id=call.id,
        sender_id=client.id,
        recipient_id=payload.recipient_id,
        ciphertext=payload.ciphertext,
    )
    db.add(signal)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "signal id already exists"
        ) from exc
    db.refresh(signal)
    events.publish("calls")
    return signal


@router.get("/calls/{call_id}/signals", response_model=list[CallSignalOut])
def list_signals(
    call_id: str,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> list[CallSignal]:
    visible_active_call(db, call_id, client.id)
    if db.get(CallParticipant, {"call_id": call_id, "client_id": client.id}) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not in call")
    return list(
        db.scalars(
            select(CallSignal)
            .where(
                and_(
                    CallSignal.call_id == call_id,
                    CallSignal.recipient_id == client.id,
                )
            )
            .order_by(CallSignal.created_at, CallSignal.id)
        )
    )
