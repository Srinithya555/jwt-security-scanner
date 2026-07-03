"""
Generates real, working JWT fixtures — some intentionally vulnerable, one
clean — used by tests and the demo. All tokens are genuinely
encoded/signed (using PyJWT where applicable), not hand-typed strings, so
the scanner is tested against real token structure.

Run: python fixtures/generate_fixtures.py
"""
import base64
import hashlib
import hmac
import json
import os
import time


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_hs256_token(header_extra: dict, payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT", **header_extra}
    header_b64 = b64url(json.dumps(header).encode())
    payload_b64 = b64url(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(sig)}"


def make_alg_none_token(payload: dict, alg_value: str = "none") -> str:
    header = {"alg": alg_value, "typ": "JWT"}
    header_b64 = b64url(json.dumps(header).encode())
    payload_b64 = b64url(json.dumps(payload).encode())
    return f"{header_b64}.{payload_b64}."


FIXTURES_DIR = os.path.dirname(os.path.abspath(__file__))

FIXTURES = {
    "weak_secret.jwt": make_hs256_token(
        {}, {"sub": "user123", "iat": int(time.time()), "exp": int(time.time()) + 300}, "secret"
    ),
    "alg_none.jwt": make_alg_none_token(
        {"sub": "attacker", "role": "admin", "iat": int(time.time())}
    ),
    "alg_none_case_variant.jwt": make_alg_none_token(
        {"sub": "attacker", "role": "admin"}, alg_value="None"
    ),
    "no_expiry.jwt": make_hs256_token(
        {}, {"sub": "user456", "iat": int(time.time())}, "a-reasonably-long-random-secret-xyz-123"
    ),
    "sensitive_data.jwt": make_hs256_token(
        {}, {
            "sub": "user789", "email": "alice@example.com", "password": "hunter2",
            "iat": int(time.time()), "exp": int(time.time()) + 300,
        }, "a-reasonably-long-random-secret-xyz-123"
    ),
    "long_lived.jwt": make_hs256_token(
        {}, {"sub": "user999", "iat": int(time.time()), "exp": int(time.time()) + 365 * 86400},
        "a-reasonably-long-random-secret-xyz-123"
    ),
    "kid_path_traversal.jwt": make_hs256_token(
        {"kid": "../../../../etc/passwd"},
        {"sub": "user321", "iat": int(time.time()), "exp": int(time.time()) + 300},
        "a-reasonably-long-random-secret-xyz-123"
    ),
    "clean_token.jwt": make_hs256_token(
        {"kid": "key-1"},
        {"sub": "user555", "iat": int(time.time()), "exp": int(time.time()) + 300},
        "a-genuinely-long-high-entropy-secret-that-would-not-be-in-any-wordlist-9f8e7d6c5b4a"
    ),
}


def main():
    for filename, token in FIXTURES.items():
        path = os.path.join(FIXTURES_DIR, filename)
        with open(path, "w") as f:
            f.write(token)
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
