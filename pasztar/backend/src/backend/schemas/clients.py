import base64
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    computed_field,
    field_validator,
)

from backend.core.db.models import now
from backend.core.settings import settings


class ClientUpdate(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    display_name: str = Field(min_length=1, max_length=120)
    public_key: str = Field(min_length=1, max_length=44)
    encryption_public_key: str = Field(min_length=1, max_length=124)

    @field_validator("public_key", "encryption_public_key")
    @classmethod
    def validate_key(cls, value, info):
        # These lengths/formats are fixed by Ed25519 and P-256 SPKI, not policy.
        raw = base64.b64decode(value, validate=True)
        if base64.b64encode(raw).decode() != value:
            raise ValueError("public key must use canonical base64")
        if info.field_name == "public_key":
            ed25519.Ed25519PublicKey.from_public_bytes(raw)
        else:
            key = serialization.load_der_public_key(raw)
            if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
                key.curve, ec.SECP256R1
            ):
                raise ValueError("encryption key must be P-256 SPKI")
        return value


class ClientCreate(ClientUpdate):
    admission_token: SecretStr | None = Field(default=None, max_length=512)


class RegistrationOut(BaseModel):
    mode: Literal["open", "bootstrap", "invitation"]


class InvitationOut(BaseModel):
    token: str
    expires_at: datetime


class ClientOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    display_name: str
    public_key: str
    encryption_public_key: str | None
    fingerprint: str
    last_seen: datetime

    @computed_field
    @property
    def inactive(self) -> bool:
        last_seen = self.last_seen
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=UTC)
        return last_seen < now() - timedelta(days=settings.identity_inactive_days)


class HeartbeatOut(BaseModel):
    last_seen: datetime
