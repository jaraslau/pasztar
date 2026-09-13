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


def test_retention_and_security_settings_from_environment(monkeypatch):
    for key, value in {
        "IDENTITY_INACTIVE_DAYS": "8",
        "IDENTITY_CLEANUP_DAYS": "60",
        "IDENTITY_CLEANUP_INTERVAL_SECONDS": "15",
        "IDENTITY_CLEANUP_BATCH_SIZE": "3",
        "TURN_CREDENTIALS_LIFETIME_SECONDS": "120",
        "INVITATION_LIFETIME_HOURS": "12",
        "EVENT_KEEPALIVE_SECONDS": "10",
    }.items():
        monkeypatch.setenv(key, value)
    config = Settings(_env_file=None)
    assert (config.identity_inactive_days, config.identity_cleanup_days) == (8, 60)
    assert (
        config.identity_cleanup_interval_seconds,
        config.identity_cleanup_batch_size,
    ) == (15, 3)
    assert config.turn_credentials_lifetime_seconds == 120
    assert config.invitation_lifetime_hours == 12
    assert config.event_keepalive_seconds == 10
    with pytest.raises(ValidationError):
        Settings(_env_file=None, identity_cleanup_days=8)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, identity_cleanup_interval_seconds=0)


def test_settings_requires_database_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_host="127.0.0.1", app_port=9000)
