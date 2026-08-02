from fastapi import HTTPException, Response, status

from backend.core.db.models import Client
from backend.schemas.clients import ClientCreate


def same_registration(client: Client, payload: ClientCreate) -> bool:
    return (
        client.display_name == payload.display_name
        and client.public_key == payload.public_key
        and client.encryption_public_key == payload.encryption_public_key
    )


def existing_registration(
    client: Client | None,
    payload: ClientCreate,
    response: Response,
) -> Client:
    if client is not None and same_registration(client, payload):
        response.status_code = status.HTTP_200_OK
        return client
    raise HTTPException(status.HTTP_409_CONFLICT, "client already exists")
