from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from backend.core.settings import settings


class MessageCreate(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    recipient_id: str = Field(min_length=1, max_length=80)
    reply_to_id: str | None = Field(default=None, min_length=1, max_length=80)
    ciphertext: str = Field(
        min_length=1,
        max_length=settings.message_ciphertext_max_length,
    )


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
