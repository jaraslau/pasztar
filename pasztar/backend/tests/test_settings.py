import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite://")

import pytest
from backend.core.settings import Settings
from pydantic import ValidationError


def test_settings_loads_env_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    for key in [
        "DATABASE_URL",
        "APP_HOST",
        "APP_PORT",
        "DEBUG_MODE",
        "TRUSTED_IDENTITIES",
        "BOOTSTRAP_TOKEN",
        "SIGNATURE_MAX_SKEW_SECONDS",
        "CALL_ICE_SERVERS",
        "CALL_STALE_AFTER_SECONDS",
        "CALL_SIGNAL_STALE_AFTER_SECONDS",
        "CALL_SIGNAL_MAX_LENGTH",
        "MESSAGE_CIPHERTEXT_MAX_LENGTH",
        "MESSAGE_LIST_DEFAULT_LIMIT",
        "MESSAGE_LIST_MAX_LIMIT",
    ]:
        monkeypatch.delenv(key, raising=False)

    env_file = tmp_path / ".env"
    env_file.write_text(
        """DATABASE_URL=sqlite://
APP_HOST=127.0.0.1
APP_PORT=9000
DEBUG_MODE=true
TRUSTED_IDENTITIES=true
BOOTSTRAP_TOKEN=bootstrap-secret
SIGNATURE_MAX_SKEW_SECONDS=42
CALL_ICE_SERVERS=[{"urls":"stun:stun.example.test:3478"}]
CALL_STALE_AFTER_SECONDS=44
CALL_SIGNAL_STALE_AFTER_SECONDS=601
CALL_SIGNAL_MAX_LENGTH=1024
MESSAGE_CIPHERTEXT_MAX_LENGTH=2048
MESSAGE_LIST_DEFAULT_LIMIT=12
MESSAGE_LIST_MAX_LIMIT=34
EXTRA_VALUE=ignored"""
    )

    settings = Settings(_env_file=env_file)

    assert settings.database_url == "sqlite://"
    assert settings.app_host == "127.0.0.1"
    assert settings.app_port == 9000
    assert settings.debug_mode is True
    assert settings.trusted_identities is True
    assert settings.bootstrap_token == "bootstrap-secret"
    assert settings.signature_max_skew_seconds == 42
    assert settings.call_ice_servers == [{"urls": "stun:stun.example.test:3478"}]
    assert settings.call_stale_after_seconds == 44
    assert settings.call_signal_stale_after_seconds == 601
    assert settings.call_signal_max_length == 1024
    assert settings.message_ciphertext_max_length == 2048
    assert settings.message_list_default_limit == 12
    assert settings.message_list_max_limit == 34


def test_settings_requires_database_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_host="127.0.0.1", app_port=9000)
