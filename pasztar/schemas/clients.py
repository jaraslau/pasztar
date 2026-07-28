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


class HeartbeatOut(BaseModel):
    last_seen: datetime
