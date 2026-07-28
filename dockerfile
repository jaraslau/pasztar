FROM python:3.12-slim

ENV POETRY_VERSION=1.8.4 \
    POETRY_VIRTUALENVS_CREATE=false \
    PYTHONUNBUFFERED=1

WORKDIR /srv/pasztar

RUN pip install "poetry==$POETRY_VERSION"

COPY pyproject.toml poetry.lock readme ./
COPY pasztar ./pasztar
COPY migrations ./migrations
COPY alembic.ini entrypoint.sh ./

RUN poetry install --only main --no-interaction --no-ansi
RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
