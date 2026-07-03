"""
Run: pytest tests/ -v
(or use the manual runner shown in README if pytest isn't installed)
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.decoder import decode, MalformedTokenError
from scanner.checks import (
    check_alg_none, check_missing_exp, check_long_lived_token, check_missing_iat,
    check_sensitive_data_in_payload, check_kid_header_injection, check_crit_header,
    check_alg_confusion_risk, check_none_case_variation, Severity,
)
from scanner.brute_force import try_secret, brute_force
from fixtures.generate_fixtures import make_hs256_token, make_alg_none_token


class TestDecoder:
    def test_decodes_valid_token(self):
        token = make_hs256_token({}, {"sub": "u1"}, "secret")
        d = decode(token)
        assert d.header["alg"] == "HS256"
        assert d.payload["sub"] == "u1"

    def test_rejects_malformed_token(self):
        try:
            decode("not.a.valid.jwt.too.many.parts")
            assert False, "expected MalformedTokenError"
        except MalformedTokenError:
            pass

    def test_rejects_non_json_payload(self):
        import base64
        garbage = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
        try:
            decode(f"{garbage}.{garbage}.sig")
            assert False, "expected MalformedTokenError"
        except MalformedTokenError:
            pass


class TestAlgNoneCheck:
    def test_detects_alg_none(self):
        findings = check_alg_none({"alg": "none"})
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_does_not_flag_rs256(self):
        assert check_alg_none({"alg": "RS256"}) == []

    def test_detects_case_variant_none(self):
        findings = check_none_case_variation({"alg": "None"})
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_lowercase_none_not_flagged_as_variant(self):
        # exact "none" is caught by check_alg_none, not the variant check
        assert check_none_case_variation({"alg": "none"}) == []


class TestExpiryChecks:
    def test_missing_exp_flagged(self):
        findings = check_missing_exp({"sub": "u1"})
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_present_exp_not_flagged(self):
        assert check_missing_exp({"exp": int(time.time()) + 300}) == []

    def test_long_lived_token_flagged(self):
        now = int(time.time())
        findings = check_long_lived_token({"iat": now, "exp": now + 400 * 86400})
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_short_lived_token_not_flagged(self):
        now = int(time.time())
        assert check_long_lived_token({"iat": now, "exp": now + 300}) == []


class TestSensitiveDataCheck:
    def test_flags_password_key(self):
        findings = check_sensitive_data_in_payload({"sub": "u1", "password": "hunter2"})
        assert any("password" in f.title for f in findings)

    def test_flags_nested_sensitive_key(self):
        findings = check_sensitive_data_in_payload({"user": {"credit_card": "4111..."}})
        assert any("credit_card" in f.title for f in findings)

    def test_clean_payload_not_flagged(self):
        findings = check_sensitive_data_in_payload({"sub": "u1", "role": "user"})
        assert findings == []


class TestKidInjectionCheck:
    def test_flags_path_traversal(self):
        findings = check_kid_header_injection({"kid": "../../etc/passwd"})
        assert any("traversal" in f.title for f in findings)

    def test_flags_sql_injection_pattern(self):
        findings = check_kid_header_injection({"kid": "1' OR '1'='1"})
        assert any("SQL injection" in f.title for f in findings)

    def test_flags_url_kid(self):
        findings = check_kid_header_injection({"kid": "https://evil.example.com/key.pem"})
        assert any("SSRF" in f.title for f in findings)

    def test_benign_kid_not_flagged(self):
        assert check_kid_header_injection({"kid": "key-1"}) == []

    def test_missing_kid_not_flagged(self):
        assert check_kid_header_injection({}) == []


class TestBruteForce:
    def test_finds_known_weak_secret(self):
        token = make_hs256_token({}, {"sub": "u1"}, "secret")
        d = decode(token)
        guessed = brute_force(d.signing_input, d.signature_b64, "HS256", ["password", "secret", "admin"])
        assert guessed == "secret"

    def test_does_not_match_wrong_secret(self):
        token = make_hs256_token({}, {"sub": "u1"}, "a-very-long-real-secret-9f8e7d")
        d = decode(token)
        guessed = brute_force(d.signing_input, d.signature_b64, "HS256", ["password", "secret", "admin"])
        assert guessed is None

    def test_rs256_not_attempted(self):
        """Brute force only makes sense for symmetric algorithms."""
        token = make_hs256_token({}, {"sub": "u1"}, "secret")
        d = decode(token)
        guessed = brute_force(d.signing_input, d.signature_b64, "RS256", ["secret"])
        assert guessed is None


class TestCritHeaderCheck:
    def test_flags_crit_header(self):
        findings = check_crit_header({"crit": ["exp"]})
        assert len(findings) == 1

    def test_no_crit_not_flagged(self):
        assert check_crit_header({}) == []
