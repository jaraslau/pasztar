from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


MAX_SIGNAL_LENGTH = 256 * 1024


class CallCreate(BaseModel):
    recipient_id: str = Field(min_length=1, max_length=80)


class CallOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    client_a_id: str
    client_b_id: str
    started_by_id: str
    created_at: datetime
    ended_at: datetime | None
    participants: list[str]


class CallConfigOut(BaseModel):
    ice_servers: list[dict[str, Any]]


class CallSignalCreate(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    recipient_id: str = Field(min_length=1, max_length=80)
    ciphertext: str = Field(min_length=1, max_length=MAX_SIGNAL_LENGTH)


class CallSignalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    call_id: str
    sender_id: str
    recipient_id: str
    ciphertext: str
    created_at: datetime
