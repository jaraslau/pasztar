#!/bin/sh
set -e

alembic upgrade head

exec uvicorn pasztar.app:app --host "$APP_HOST" --port "$APP_PORT"
