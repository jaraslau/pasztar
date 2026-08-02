import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite://")

import pytest
from pydantic import ValidationError

from backend.core.settings import Settings


def test_settings_loads_env_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    for key in [
        "DATABASE_URL",
        "APP_HOST",
        "APP_PORT",
        "DEBUG_MODE",
        "SIGNATURE_MAX_SKEW_SECONDS",
        "CALL_ICE_SERVERS",
    ]:
        monkeypatch.delenv(key, raising=False)

    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "DATABASE_URL=sqlite://",
                "APP_HOST=127.0.0.1",
                "APP_PORT=9000",
                "DEBUG_MODE=true",
                "SIGNATURE_MAX_SKEW_SECONDS=42",
                'CALL_ICE_SERVERS=[{"urls":"stun:stun.example.test:3478"}]',
                "EXTRA_VALUE=ignored",
            ]
        )
    )

    settings = Settings(_env_file=env_file)

    assert settings.database_url == "sqlite://"
    assert settings.app_host == "127.0.0.1"
    assert settings.app_port == 9000
    assert settings.debug_mode is True
    assert settings.signature_max_skew_seconds == 42
    assert settings.call_ice_servers == [{"urls": "stun:stun.example.test:3478"}]


def test_settings_requires_database_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_host="127.0.0.1", app_port=9000)
