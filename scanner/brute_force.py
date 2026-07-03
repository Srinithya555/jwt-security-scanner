"""
Attempts to guess the HMAC secret used to sign an HS256/HS384/HS512 token
against a wordlist of known-weak/common secrets. This mirrors what tools
like jwt_tool and hashcat's JWT mode do, and is directly useful during a
pentest engagement: a huge number of real-world JWT implementations use a
weak, default, or accidentally-committed secret (e.g. copied from a
tutorial and never changed — "your-256-bit-secret" is a genuinely common
one because it's the literal placeholder in jwt.io's debugger).

Only applies to symmetric algorithms (HS*). RS256/ES256 use asymmetric
keys and cannot be brute-forced this way from the token alone.
"""
import hashlib
import hmac as hmac_module


_HASH_FOR_ALG = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def try_secret(signing_input: str, signature_b64: str, secret: str, alg: str) -> bool:
    import base64
    hash_fn = _HASH_FOR_ALG.get(alg.upper())
    if hash_fn is None:
        return False
    computed = hmac_module.new(secret.encode(), signing_input.encode(), hash_fn).digest()
    computed_b64 = base64.urlsafe_b64encode(computed).rstrip(b"=").decode()

    padding = "=" * (-len(signature_b64) % 4)
    try:
        provided = base64.urlsafe_b64decode(signature_b64 + padding)
    except Exception:
        return False
    return hmac_module.compare_digest(computed, provided)


def brute_force(signing_input: str, signature_b64: str, alg: str, wordlist: list) -> str | None:
    """Returns the guessed secret if found, else None. Only meaningful for HS* algorithms."""
    if alg.upper() not in _HASH_FOR_ALG:
        return None
    for candidate in wordlist:
        if try_secret(signing_input, signature_b64, candidate, alg):
            return candidate
    return None


def load_wordlist(path: str) -> list:
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]
