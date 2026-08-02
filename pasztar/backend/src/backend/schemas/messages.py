from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

MAX_CIPHERTEXT_LENGTH = 16 * 1024 * 1024


class MessageCreate(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    recipient_id: str = Field(min_length=1, max_length=80)
    reply_to_id: str | None = Field(default=None, min_length=1, max_length=80)
    ciphertext: str = Field(min_length=1, max_length=MAX_CIPHERTEXT_LENGTH)


class MessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sender_id: str
    recipient_id: str
    reply_to_id: str | None
    ciphertext: str
    created_at: datetime
    delivered_at: datetime | None
    read_at: datetime | None
