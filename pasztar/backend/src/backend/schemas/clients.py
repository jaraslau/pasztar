from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class ClientCreate(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    display_name: str = Field(min_length=1, max_length=120)
    public_key: str = Field(min_length=1)
    encryption_public_key: str = Field(min_length=1)
    admission_token: SecretStr | None = Field(default=None, max_length=512)


class RegistrationOut(BaseModel):
    mode: Literal["open", "bootstrap", "invitation"]


class InvitationOut(BaseModel):
    token: str
    expires_at: datetime


class ClientUpdate(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    display_name: str = Field(min_length=1, max_length=120)
    public_key: str = Field(min_length=1)
    encryption_public_key: str = Field(min_length=1)


class ClientOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    display_name: str
    public_key: str
    encryption_public_key: str | None
    fingerprint: str
    last_seen: datetime


class HeartbeatOut(BaseModel):
    last_seen: datetime
