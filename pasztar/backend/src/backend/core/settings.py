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
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    signature_max_skew_seconds: int = 300
    call_ice_servers: list[dict[str, Any]] = Field(default_factory=list)


settings = Settings()
