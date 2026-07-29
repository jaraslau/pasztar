import argparse
import base64
import json
import sys
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pasztar.core.signing import fingerprint, signature_payload


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def private_from_b64(value: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(value))


def request_json(
    base_url: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    client_id: str | None = None,
    private_key: Ed25519PrivateKey | None = None,
) -> Any:
    body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    headers = {"Content-Type": "application/json"}

    if client_id and private_key:
        timestamp = datetime.now(UTC).isoformat()
        nonce = str(uuid.uuid4())
        parsed_url = urlsplit(url)
        signed_path = parsed_url.path
        if parsed_url.query:
            signed_path = f"{signed_path}?{parsed_url.query}"
        signature = private_key.sign(
            signature_payload(method, signed_path, timestamp, nonce, body)
        )
        headers.update(
            {
                "X-Client-Id": client_id,
                "X-Timestamp": timestamp,
                "X-Nonce": nonce,
                "X-Signature": b64(signature),
            }
        )

    try:
        request = Request(url, data=body or None, headers=headers, method=method)
        with urlopen(request) as response:
            data = response.read()
    except HTTPError as exc:
        sys.exit(f"{exc.code}: {exc.read().decode()}")

    return None if not data else json.loads(data)


def keygen(_: argparse.Namespace) -> None:
    private_key = Ed25519PrivateKey.generate()
    private = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    public_b64 = b64(public)
    print(
        json.dumps(
            {
                "private_key": b64(private),
                "public_key": public_b64,
                "fingerprint": fingerprint(public_b64),
            },
            indent=2,
        )
    )


def register(args: argparse.Namespace) -> None:
    print(
        json.dumps(
            request_json(
                args.url,
                "POST",
                "/clients",
                {
                    "id": args.client_id,
                    "display_name": args.display_name,
                    "public_key": args.public_key,
                },
            ),
            indent=2,
        )
    )


def send(args: argparse.Namespace) -> None:
    print(
        json.dumps(
            request_json(
                args.url,
                "POST",
                "/messages",
                {
                    "id": args.message_id or str(uuid.uuid4()),
                    "recipient_id": args.recipient_id,
                    "ciphertext": args.ciphertext,
                },
                args.client_id,
                private_from_b64(args.private_key),
            ),
            indent=2,
        )
    )


def fetch(args: argparse.Namespace) -> None:
    query = urlencode(
        {
            key: value
            for key, value in {"since": args.since, "limit": args.limit}.items()
            if value is not None
        }
    )
    path = "/messages" if not query else f"/messages?{query}"
    print(
        json.dumps(
            request_json(
                args.url,
                "GET",
                path,
                client_id=args.client_id,
                private_key=private_from_b64(args.private_key),
            ),
            indent=2,
        )
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="pasztar")
    root.add_argument("--url", default="http://localhost:8000")
    subcommands = root.add_subparsers(required=True)

    keygen_cmd = subcommands.add_parser("keygen")
    keygen_cmd.set_defaults(func=keygen)

    register_cmd = subcommands.add_parser("register")
    register_cmd.add_argument("--client-id", required=True)
    register_cmd.add_argument("--display-name", required=True)
    register_cmd.add_argument("--public-key", required=True)
    register_cmd.set_defaults(func=register)

    send_cmd = subcommands.add_parser("send")
    send_cmd.add_argument("--client-id", required=True)
    send_cmd.add_argument("--private-key", required=True)
    send_cmd.add_argument("--recipient-id", required=True)
    send_cmd.add_argument("--ciphertext", required=True)
    send_cmd.add_argument("--message-id")
    send_cmd.set_defaults(func=send)

    fetch_cmd = subcommands.add_parser("fetch")
    fetch_cmd.add_argument("--client-id", required=True)
    fetch_cmd.add_argument("--private-key", required=True)
    fetch_cmd.add_argument("--since")
    fetch_cmd.add_argument("--limit", type=int, default=100)
    fetch_cmd.set_defaults(func=fetch)
    return root


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
