"""
Individual security checks run against a decoded (not necessarily verified)
JWT. Each check is independent and returns zero or more Findings — this
structure mirrors how real scanners (Nuclei templates, Semgrep rules) are
organized: small, single-purpose, independently testable units rather than
one large monolithic "scan" function.
"""
import re
import time
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str


# Real-world CVEs and disclosures this check set is directly informed by:
# - CVE-2015-9235 (jsonwebtoken alg confusion / none acceptance)
# - CVE-2016-5431 / CVE-2016-10555 (RS256/HS256 confusion in multiple JWT libs)
# - Auth0's "Critical vulnerabilities in JSON Web Token libraries" writeup (2015)


def check_alg_none(header: dict) -> list:
    alg = str(header.get("alg", ""))
    if alg.strip().lower() == "none":
        return [Finding(
            Severity.CRITICAL,
            "alg=none accepted",
            f"Header declares alg='{alg}'. Any verifier that honors this literally accepts "
            "unsigned tokens — an attacker can set any claims they want with zero signing "
            "key knowledge. A correctly configured verifier must pin the expected algorithm "
            "and never trust the alg value from the token itself.",
        )]
    return []


def check_missing_exp(payload: dict) -> list:
    if "exp" not in payload:
        return [Finding(
            Severity.HIGH,
            "Missing 'exp' (expiration) claim",
            "Tokens without an expiration are valid forever once issued. If leaked (logs, "
            "browser history, a compromised client), there is no time-based limit on misuse.",
        )]
    return []


def check_long_lived_token(payload: dict, max_lifetime_seconds: int = 30 * 24 * 3600) -> list:
    if "exp" not in payload or "iat" not in payload:
        return []
    lifetime = payload["exp"] - payload["iat"]
    if lifetime > max_lifetime_seconds:
        days = lifetime / 86400
        return [Finding(
            Severity.MEDIUM,
            "Unusually long token lifetime",
            f"Token is valid for {days:.1f} days. Long-lived access tokens increase the "
            "blast radius of a leak. Consider short-lived access tokens (minutes, not weeks) "
            "paired with a separate refresh token flow.",
        )]
    return []


def check_missing_iat(payload: dict) -> list:
    if "iat" not in payload:
        return [Finding(
            Severity.LOW,
            "Missing 'iat' (issued-at) claim",
            "Without iat, it's harder to enforce token-lifetime policies or detect clock-skew "
            "issues during verification.",
        )]
    return []


_SENSITIVE_KEY_PATTERNS = re.compile(
    r"(password|passwd|secret|ssn|social_security|credit_card|card_number|cvv|api_key|private_key)",
    re.IGNORECASE,
)
_EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def check_sensitive_data_in_payload(payload: dict) -> list:
    """
    JWT payloads are base64url — NOT encrypted. Anyone holding the token
    (a browser extension, a proxy log, a misconfigured error page that
    echoes the Authorization header) can read every claim. Embedding
    secrets or excessive PII directly in the token is a common real-world
    mistake this check is designed to catch.
    """
    findings = []

    def walk(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{path}.{k}" if path else k
                if _SENSITIVE_KEY_PATTERNS.search(k):
                    findings.append(Finding(
                        Severity.HIGH,
                        f"Sensitive-looking claim key: '{key_path}'",
                        "JWT payloads are base64-encoded, not encrypted — this claim key name "
                        "suggests sensitive data may be readable by anyone with the token.",
                    ))
                walk(v, key_path)
        elif isinstance(obj, str):
            if _EMAIL_PATTERN.search(obj) and path not in ("email", "sub"):
                findings.append(Finding(
                    Severity.LOW,
                    f"Email address embedded in claim '{path}'",
                    "Consider whether this PII needs to be in the token at all, versus looked "
                    "up server-side from the subject claim.",
                ))

    walk(payload)
    return findings


def check_kid_header_injection(header: dict) -> list:
    """
    The 'kid' (key ID) header tells the verifier which key to use — and in
    real-world incidents, verifiers that use `kid` to build a file path or
    database query without sanitizing it have been exploited for path
    traversal (read arbitrary local files as if they were the signing key)
    or SQL injection. If `kid` is attacker-controlled (it's inside the
    token, so yes) and a verifier ever does `open(f"keys/{kid}.pem")` or
    similar, this is directly exploitable.
    """
    kid = header.get("kid")
    if not isinstance(kid, str):
        return []
    findings = []
    if ".." in kid or kid.startswith("/"):
        findings.append(Finding(
            Severity.HIGH,
            "Suspicious 'kid' header value (path traversal pattern)",
            f"kid='{kid}' contains path traversal characters. If the verifying service builds "
            "a file path from this value without sanitization, an attacker could point it at "
            "an arbitrary local file (e.g. /dev/null, which some libraries then treat as an "
            "empty HMAC secret) to forge tokens.",
        ))
    if re.search(r"['\";]|(\bOR\b|\bUNION\b)", kid, re.IGNORECASE):
        findings.append(Finding(
            Severity.HIGH,
            "Suspicious 'kid' header value (SQL injection pattern)",
            f"kid='{kid}' contains characters/keywords associated with SQL injection. If the "
            "verifying service looks up a key by this value in a database without "
            "parameterized queries, this is directly exploitable.",
        ))
    if kid.startswith("http://") or kid.startswith("https://"):
        findings.append(Finding(
            Severity.HIGH,
            "'kid' header contains a URL (possible SSRF vector)",
            f"kid='{kid}'. Some JWT libraries historically supported fetching a JWK from a "
            "URL specified in the header (jku/x5u, sometimes kid depending on implementation). "
            "If the verifier fetches this URL, an attacker fully controls both the request "
            "target AND the key used to 'verify' their own forged token.",
        ))
    return findings


def check_crit_header(header: dict) -> list:
    if "crit" in header:
        return [Finding(
            Severity.MEDIUM,
            "'crit' (critical) header present",
            f"crit={header['crit']}. Per RFC 7515, a verifier MUST reject the token if it "
            "doesn't understand every header listed in 'crit'. Historically, JOSE library "
            "bugs around crit-header handling have been a source of verification bypasses — "
            "worth confirming the verifying library correctly enforces this rather than "
            "ignoring unknown crit values.",
        )]
    return []


def check_alg_confusion_risk(header: dict) -> list:
    alg = str(header.get("alg", ""))
    if alg.upper() == "HS256":
        return [Finding(
            Severity.INFO,
            "Token uses HS256 (symmetric) — confirm the verifier doesn't ALSO accept RS256",
            "This isn't a flaw in the token itself, but a known attack class: if the same "
            "verifying endpoint also accepts RS256 tokens, and an attacker knows the RS256 "
            "public key (often published, e.g. at a JWKS endpoint), they can craft an HS256 "
            "token HMAC-signed using the public key STRING as the shared secret. A verifier "
            "that doesn't pin exactly one expected algorithm may accept it. Not exploitable "
            "from the token alone — flagged so you check the verifying service's algorithm "
            "allow-list.",
        )]
    return []


def check_none_case_variation(header: dict) -> list:
    alg = str(header.get("alg", ""))
    if alg.lower() == "none" and alg != "none":
        return [Finding(
            Severity.HIGH,
            f"Case-variant 'none' algorithm: '{alg}'",
            "Some historical JWT library vulnerabilities (e.g. early jsonwebtoken versions) "
            "compared alg case-sensitively against 'none' but the underlying crypto dispatch "
            "was case-insensitive, allowing variants like 'None' or 'NONE' to slip past "
            "naive checks. Confirm the verifying library normalizes case before comparison.",
        )]
    return []


def check_expired(payload: dict) -> list:
    if "exp" in payload and isinstance(payload["exp"], (int, float)):
        if payload["exp"] < time.time():
            return [Finding(
                Severity.INFO,
                "Token is expired",
                "This specific token instance is already expired. Informational only — "
                "doesn't indicate a flaw in how the token was constructed.",
            )]
    return []


ALL_CHECKS = [
    check_alg_none,
    check_none_case_variation,
    check_alg_confusion_risk,
    check_kid_header_injection,
    check_crit_header,
]

PAYLOAD_CHECKS = [
    check_missing_exp,
    check_missing_iat,
    check_long_lived_token,
    check_sensitive_data_in_payload,
    check_expired,
]


def run_header_checks(header: dict) -> list:
    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(header))
    return findings


def run_payload_checks(payload: dict) -> list:
    findings = []
    for check in PAYLOAD_CHECKS:
        findings.extend(check(payload))
    return findings
