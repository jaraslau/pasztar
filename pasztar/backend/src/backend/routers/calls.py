from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.auth import require_client
from backend.core.db.models import Call, CallParticipant, CallSignal, Client, now
from backend.core.db.session import get_db
from backend.core.events import events
from backend.core.helpers.calls import (
    active_call_for_pair,
    call_out,
    call_pair,
    clear_signals_for,
    end_empty_calls,
    join_call,
    leave_other_calls,
    prune_stale_calls,
    visible_active_call,
)
from backend.core.settings import settings
from backend.schemas.calls import (
    CallConfigOut,
    CallCreate,
    CallOut,
    CallSignalCreate,
    CallSignalOut,
)

router = APIRouter()


@router.get("/calls/config", response_model=CallConfigOut)
def call_config(_: Client = Depends(require_client)) -> CallConfigOut:
    return CallConfigOut(ice_servers=settings.call_ice_servers)


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
) -> CallSignalOut:
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
    response = CallSignalOut.model_validate(signal)
    events.publish("calls")
    return response


@router.get("/calls/{call_id}/signals", response_model=list[CallSignalOut])
def list_signals(
    call_id: str,
    db: Session = Depends(get_db),
    client: Client = Depends(require_client),
) -> list[CallSignalOut]:
    visible_active_call(db, call_id, client.id)
    if db.get(CallParticipant, {"call_id": call_id, "client_id": client.id}) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not in call")
    signals = list(
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
    response = [CallSignalOut.model_validate(signal) for signal in signals]
    for signal in signals:
        db.delete(signal)
    if signals:
        db.commit()
    return response
