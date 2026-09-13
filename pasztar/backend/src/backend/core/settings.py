from typing import Any

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str
    debug_mode: bool = False
    trusted_identities: bool = False
    bootstrap_token: str | None = None
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    signature_max_skew_seconds: int = Field(default=300, gt=0)
    invitation_lifetime_hours: int = Field(default=24, gt=0)
    event_keepalive_seconds: int = Field(default=25, gt=0)
    identity_inactive_days: int = Field(default=7, gt=0)
    identity_cleanup_days: int = Field(default=90, gt=0)
    identity_cleanup_interval_seconds: int = Field(default=3600, gt=0)
    identity_cleanup_batch_size: int = Field(default=100, gt=0)
    call_ice_servers: list[dict[str, Any]] = Field(default_factory=list)
    turn_shared_secret: SecretStr | None = None
    turn_credentials_lifetime_seconds: int = Field(default=3600, gt=0)
    call_stale_after_seconds: int = 45
    call_signal_stale_after_seconds: int = 600
    call_signal_max_length: int = 256 * 1024
    message_ciphertext_max_length: int = 160 * 1024 * 1024
    message_list_default_limit: int = 100
    message_list_max_limit: int = 500

    @model_validator(mode="after")
    def validate_retention(self):
        if self.identity_cleanup_days <= self.identity_inactive_days:
            raise ValueError("IDENTITY_CLEANUP_DAYS must exceed IDENTITY_INACTIVE_DAYS")
        return self


settings = Settings()
