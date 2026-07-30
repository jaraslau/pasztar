import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("REGISTRATION_TOKEN_SECRET", "test-secret")

import pytest
from pydantic import ValidationError

from pasztar.backend.core.settings import Settings


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
        "REGISTRATION_TOKEN_SECRET",
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
                "REGISTRATION_TOKEN_SECRET=test-secret",
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
    assert settings.registration_token_secret == "test-secret"


def test_settings_requires_database_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_host="127.0.0.1", app_port=9000)
