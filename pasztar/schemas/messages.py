from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


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
