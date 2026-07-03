"""
Decodes a JWT's header and payload WITHOUT verifying the signature.

This is intentional and necessary for a security scanner: you're auditing
a token you don't control (someone else's API, a token you intercepted
during a pentest engagement, a sample from a bug bounty target), so you
usually don't have the signing key. Everything this module does is exactly
what an attacker inspecting a captured token would also see — JWTs are
base64url-encoded, NOT encrypted, so the header and payload are always
readable by anyone who has the token string, verified signature or not.
That fact is itself the basis of one of the checks in checks.py
(sensitive data embedded in the payload).
"""
import base64
import json
from dataclasses import dataclass


class MalformedTokenError(Exception):
    pass


@dataclass
class DecodedToken:
    raw: str
    header: dict
    payload: dict
    signature_b64: str
    signing_input: str  # "header_b64.payload_b64" - what the signature was computed over


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode(token: str) -> DecodedToken:
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise MalformedTokenError(
            f"Expected 3 dot-separated segments (header.payload.signature), got {len(parts)}"
        )
    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as e:
        raise MalformedTokenError(f"Header is not valid base64url-encoded JSON: {e}") from e

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        raise MalformedTokenError(f"Payload is not valid base64url-encoded JSON: {e}") from e

    return DecodedToken(
        raw=token,
        header=header,
        payload=payload,
        signature_b64=signature_b64,
        signing_input=f"{header_b64}.{payload_b64}",
    )
