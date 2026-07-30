import base64
import binascii
import hashlib
import hmac
import json


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def issue_identity_token(client_id: str, secret: str) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": client_id}).encode())
    signing_input = f"{header}.{payload}"
    signature = hmac.new(
        secret.encode(),
        signing_input.encode(),
        hashlib.sha256,
    ).digest()
    return f"{signing_input}.{_b64url(signature)}"


def valid_identity_token(token: str, client_id: str, secret: str) -> bool:
    try:
        header, payload, signature = token.split(".")
        signing_input = f"{header}.{payload}"
        expected = hmac.new(
            secret.encode(),
            signing_input.encode(),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(_unb64url(signature), expected):
            return False
        if json.loads(_unb64url(header)).get("alg") != "HS256":
            return False
        return json.loads(_unb64url(payload)).get("sub") == client_id
    except (ValueError, json.JSONDecodeError, binascii.Error):
        return False
