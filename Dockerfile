FROM python:3.12-slim

ENV POETRY_VERSION=1.8.4 \
    POETRY_VIRTUALENVS_CREATE=false \
    PYTHONUNBUFFERED=1

WORKDIR /srv/pasztar

RUN pip install "poetry==$POETRY_VERSION"

COPY pyproject.toml poetry.lock readme ./
COPY pasztar ./pasztar

RUN poetry install --only main --no-interaction --no-ansi

EXPOSE 8000
CMD ["uvicorn", "pasztar.main:app", "--host", "0.0.0.0", "--port", "8000"]
