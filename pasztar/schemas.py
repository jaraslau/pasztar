from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ClientCreate(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    display_name: str = Field(min_length=1, max_length=120)
    public_key: str = Field(min_length=1)


class ClientOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    display_name: str
    public_key: str
    fingerprint: str
    last_seen: datetime


class MessageCreate(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    recipient_id: str = Field(min_length=1, max_length=80)
    ciphertext: str = Field(min_length=1)


class MessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sender_id: str
    recipient_id: str
    ciphertext: str
    created_at: datetime
    delivered_at: datetime | None
    read_at: datetime | None


class HeartbeatOut(BaseModel):
    last_seen: datetime
