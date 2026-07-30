import hashlib


def fingerprint(public_key: str) -> str:
    return hashlib.sha256(public_key.encode()).hexdigest()


def signature_payload(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}".encode()
