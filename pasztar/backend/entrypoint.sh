#!/bin/sh
set -e

alembic upgrade head

APP_HOST="$(python -c 'from backend.core.settings import settings; print(settings.app_host)')"
APP_PORT="$(python -c 'from backend.core.settings import settings; print(settings.app_port)')"

exec uvicorn backend.app:app --host "$APP_HOST" --port "$APP_PORT"
