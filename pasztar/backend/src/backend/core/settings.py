from typing import Any

from pydantic import Field
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
    signature_max_skew_seconds: int = 300
    call_ice_servers: list[dict[str, Any]] = Field(default_factory=list)
    call_stale_after_seconds: int = 45
    call_signal_stale_after_seconds: int = 600
    call_signal_max_length: int = 256 * 1024
    message_ciphertext_max_length: int = 160 * 1024 * 1024
    message_list_default_limit: int = 100
    message_list_max_limit: int = 500


settings = Settings()
