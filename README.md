# JWT Security Scanner

A CLI tool that inspects a JWT for common real-world misconfigurations —
`alg=none`, weak/guessable HMAC secrets, algorithm-confusion risk, `kid`
header injection, missing expiration, PII embedded in the payload, and
more. Built to be genuinely useful during a pentest engagement or CI
pipeline, not just a portfolio exercise — every check maps to a real,
documented vulnerability class (see the CVE references in
[`scanner/checks.py`](./scanner/checks.py)).

## Why this is a real tool, not a toy

JWTs are base64url-encoded, **not encrypted** — anyone holding a token can
read its header and payload without any key. That fact underlies half of
what this scanner checks: it never needs the signing key to flag most
issues, because most issues are visible from the token's structure alone.
The one thing that DOES need effort — confirming a weak secret was
actually used to sign the token — is handled by `--bruteforce`, which
tries the signature against a wordlist of known-weak secrets and
cryptographically confirms a match (not a guess: it recomputes the HMAC
and does a constant-time comparison against the real signature).

## Setup

```bash
git clone <your-fork-url>
cd jwt-security-scanner
pip install -r requirements.txt   # only needed for tests/ and fixture generation
```

No dependencies are required to run the scanner itself — `scanner/cli.py`
uses only the Python standard library, so it works anywhere Python 3.8+ is
available, which matters for a tool you might drop onto a pentest jump box
that doesn't have internet access to `pip install` anything.

## Usage

```bash
# Scan a token directly
python -m scanner.cli --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Scan a token from a file
python -m scanner.cli --file fixtures/alg_none.jwt

# Also attempt to guess a weak HMAC secret
python -m scanner.cli --file fixtures/weak_secret.jwt --bruteforce

# Use your own wordlist (e.g. a target-specific one from OSINT)
python -m scanner.cli --file token.txt --bruteforce --wordlist custom_wordlist.txt

# Machine-readable output, for piping into other tools / CI
python -m scanner.cli --file token.txt --json
```

Exit codes (designed for CI gating — e.g. fail a build if a token fixture
in your test suite regresses to `alg=none`):
- `0` — no HIGH or CRITICAL findings
- `1` — at least one HIGH or CRITICAL finding
- `2` — token could not be parsed

## Generating test fixtures

```bash
python fixtures/generate_fixtures.py
```

Produces 8 real, working JWTs — genuinely encoded and signed (not
hand-typed example strings) — covering: a weak-secret token, `alg=none`,
a case-variant `none` (`"None"`), a token missing `exp`, one with PII in
the payload, an unusually long-lived token, one with a path-traversal
`kid` header, and one clean token that should trigger no HIGH/CRITICAL
findings.

## Example run

```
$ python -m scanner.cli --file fixtures/kid_path_traversal.jwt

======================================================================
JWT SECURITY SCAN REPORT
======================================================================

Header:  {"alg": "HS256", "typ": "JWT", "kid": "../../../../etc/passwd"}
Payload: {"sub": "user321", "iat": 1234567890, "exp": 1234568190}

Findings: 2

[HIGH] Suspicious 'kid' header value (path traversal pattern)
    kid='../../../../etc/passwd' contains path traversal characters...

[INFO] Token uses HS256 (symmetric) — confirm the verifier doesn't ALSO accept RS256
    ...
```

## Running the tests

```bash
pytest tests/ -v
```

24 tests covering every check function individually plus the brute-force
matcher (including a negative test — confirming a strong secret does NOT
false-positive).

## What this scanner checks

| Check | Severity | Real-world basis |
|---|---|---|
| `alg=none` accepted | CRITICAL | CVE-2015-9235 and similar |
| Case-variant `none` (`"None"`, `"NONE"`) | HIGH | Early jsonwebtoken-style bypasses |
| Weak/guessable HMAC secret (`--bruteforce`) | CRITICAL | Extremely common in real deployments — copied tutorial secrets |
| `kid` header path traversal | HIGH | Documented JWT library exploitation pattern |
| `kid` header SQL injection pattern | HIGH | Same class, DB-backed key lookup |
| `kid`/header containing a URL | HIGH | SSRF via key-fetching JOSE implementations |
| Missing `exp` | HIGH | Token never expires if leaked |
| Unusually long token lifetime | MEDIUM | Increases blast radius of leaks |
| `crit` header present | MEDIUM | RFC 7515 handling has been a bypass source |
| Sensitive-looking claim keys (password, ssn, etc.) | HIGH | JWTs are readable, not encrypted |
| HS256 usage (alg-confusion advisory) | INFO | RS256/HS256 confusion attacks |
| Missing `iat` | LOW | Weakens lifetime/clock-skew enforcement |

## Known limitations

- Signature cryptographic validity is only confirmed for HS256/384/512 via
  `--bruteforce` matching a wordlist entry — this tool does **not** attempt
  to verify RS256/ES256 signatures (that requires the public key, which you
  should instead use directly with a library like PyJWT if you have it).
- The wordlist is intentionally small and illustrative. For real
  engagements, pair this with a much larger list (rockyou.txt-scale) and
  expect brute force to take meaningfully longer — HMAC-SHA256 is fast per
  guess, but scanning millions of candidates still takes real time; this
  tool doesn't currently parallelize the brute-force loop.
- Not a replacement for a real fuzzing/pentest toolkit like `jwt_tool` —
  this is a focused, readable implementation of a subset of the same idea,
  built to demonstrate the underlying security concepts clearly.

## License

MIT — see [LICENSE](./LICENSE).
