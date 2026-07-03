#!/usr/bin/env python3
"""
JWT Security Scanner — CLI

Usage:
    python -m scanner.cli --token "eyJhbGc..."
    python -m scanner.cli --file token.txt
    python -m scanner.cli --token "eyJhbGc..." --bruteforce
    python -m scanner.cli --token "eyJhbGc..." --bruteforce --wordlist custom.txt
    python -m scanner.cli --token "eyJhbGc..." --json

Exit codes (useful for CI gating — e.g. fail a build if a token fixture
regresses to using alg=none):
    0 = no HIGH or CRITICAL findings
    1 = at least one HIGH or CRITICAL finding
    2 = token could not be parsed
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.decoder import decode, MalformedTokenError
from scanner.checks import run_header_checks, run_payload_checks, Severity
from scanner.brute_force import brute_force, load_wordlist

DEFAULT_WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt")

SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[91m",  # red
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",    # yellow
    Severity.LOW: "\033[94m",       # blue
    Severity.INFO: "\033[90m",      # gray
}
RESET = "\033[0m"


def main():
    parser = argparse.ArgumentParser(description="Scan a JWT for common security misconfigurations.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--token", help="JWT string to scan")
    group.add_argument("--file", help="Path to a file containing a single JWT")
    parser.add_argument("--bruteforce", action="store_true",
                        help="Attempt to guess a weak HMAC secret (HS256/384/512 only)")
    parser.add_argument("--wordlist", default=DEFAULT_WORDLIST,
                        help="Path to a custom wordlist for --bruteforce")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON instead of a text report")
    args = parser.parse_args()

    token = args.token if args.token else open(args.file).read().strip()

    try:
        decoded = decode(token)
    except MalformedTokenError as e:
        print(f"ERROR: could not parse token: {e}", file=sys.stderr)
        sys.exit(2)

    findings = run_header_checks(decoded.header) + run_payload_checks(decoded.payload)

    guessed_secret = None
    if args.bruteforce:
        alg = decoded.header.get("alg", "")
        wordlist = load_wordlist(args.wordlist)
        guessed_secret = brute_force(decoded.signing_input, decoded.signature_b64, alg, wordlist)
        if guessed_secret:
            from scanner.checks import Finding
            findings.append(Finding(
                Severity.CRITICAL,
                "Weak HMAC secret guessed",
                f"Signature verified successfully using secret: '{guessed_secret}'. This "
                f"secret is on a common-weak-secrets wordlist. Anyone with this secret can "
                f"forge arbitrary valid tokens.",
            ))

    findings.sort(key=lambda f: -f.severity.value)

    if args.json:
        output = {
            "header": decoded.header,
            "payload": decoded.payload,
            "findings": [
                {"severity": f.severity.name, "title": f.title, "detail": f.detail}
                for f in findings
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print_report(decoded, findings)

    has_high_or_critical = any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
    sys.exit(1 if has_high_or_critical else 0)


def print_report(decoded, findings):
    print("=" * 70)
    print("JWT SECURITY SCAN REPORT")
    print("=" * 70)
    print(f"\nHeader:  {json.dumps(decoded.header)}")
    print(f"Payload: {json.dumps(decoded.payload)}")
    print(f"\nFindings: {len(findings)}\n")

    if not findings:
        print("No issues detected by the checks in this scanner. This does NOT mean the "
              "token/verifier is fully secure — it means none of the specific patterns this "
              "tool checks for were present. Signature validity was not itself confirmed "
              "unless --bruteforce found a match.")
        return

    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "")
        print(f"{color}[{f.severity.name}]{RESET} {f.title}")
        print(f"    {f.detail}\n")


if __name__ == "__main__":
    main()
