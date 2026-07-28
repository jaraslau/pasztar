#!/bin/sh
set -e

alembic upgrade head

APP_HOST="$(python -c 'from pasztar.core.settings import settings; print(settings.app_host)')"
APP_PORT="$(python -c 'from pasztar.core.settings import settings; print(settings.app_port)')"

exec uvicorn pasztar.app:app --host "$APP_HOST" --port "$APP_PORT"
