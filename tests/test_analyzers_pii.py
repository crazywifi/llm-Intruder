"""Tests for llm_intruder.analyzers.pii — scan_pii()."""
from __future__ import annotations

import hashlib

from llm_intruder.analyzers.pii import scan_pii
from llm_intruder.analyzers.models import PiiScanResult


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ── Clean text ─────────────────────────────────────────────────────────────────

class TestCleanText:
    def test_no_matches_on_clean_text(self):
        result = scan_pii("The weather today is sunny and warm.")
        assert result.matches == []
        assert result.risk_level == "none"

    def test_returns_pii_scan_result(self):
        result = scan_pii("hello world")
        assert isinstance(result, PiiScanResult)

    def test_response_hash_is_sha256(self):
        text = "no pii here"
        result = scan_pii(text)
        assert result.response_hash == _sha256(text)

    def test_empty_text(self):
        result = scan_pii("")
        assert result.matches == []
        assert result.risk_level == "none"


# ── Email detection ────────────────────────────────────────────────────────────

class TestEmailDetection:
    def test_simple_email(self):
        result = scan_pii("Contact us at admin@example.com for support.")
        types = {m.entity_type for m in result.matches}
        assert "EMAIL" in types

    def test_email_risk_medium(self):
        result = scan_pii("Email: user@domain.org")
        assert result.risk_level == "medium"

    def test_email_masked(self):
        result = scan_pii("user@example.com")
        email_matches = [m for m in result.matches if m.entity_type == "EMAIL"]
        assert email_matches
        assert "***" in email_matches[0].masked_value
        assert "user@example.com" not in email_matches[0].masked_value

    def test_email_counted(self):
        result = scan_pii("a@b.com and c@d.com")
        assert result.entity_counts.get("EMAIL", 0) >= 1


# ── Phone detection ────────────────────────────────────────────────────────────

class TestPhoneDetection:
    def test_dashes(self):
        result = scan_pii("Call 555-867-5309 now.")
        types = {m.entity_type for m in result.matches}
        assert "PHONE" in types

    def test_phone_risk_medium(self):
        result = scan_pii("Phone: 555-123-4567")
        assert result.risk_level == "medium"


# ── SSN detection ──────────────────────────────────────────────────────────────

class TestSsnDetection:
    def test_ssn_detected(self):
        result = scan_pii("SSN: 123-45-6789")
        types = {m.entity_type for m in result.matches}
        assert "SSN" in types

    def test_ssn_risk_high(self):
        result = scan_pii("SSN: 123-45-6789")
        assert result.risk_level == "high"

    def test_ssn_masked(self):
        result = scan_pii("Your SSN is 987-65-4321.")
        ssn = [m for m in result.matches if m.entity_type == "SSN"]
        assert ssn
        assert "987-65-4321" not in ssn[0].masked_value


# ── Credit card detection ──────────────────────────────────────────────────────

class TestCreditCardDetection:
    def test_card_with_dashes(self):
        result = scan_pii("Card: 4111-1111-1111-1111")
        types = {m.entity_type for m in result.matches}
        assert "CREDIT_CARD" in types

    def test_card_with_spaces(self):
        result = scan_pii("Card: 4111 1111 1111 1111")
        types = {m.entity_type for m in result.matches}
        assert "CREDIT_CARD" in types

    def test_card_risk_high(self):
        result = scan_pii("4111-1111-1111-1111")
        assert result.risk_level == "high"


# ── AWS key detection ──────────────────────────────────────────────────────────

class TestAwsKeyDetection:
    def test_aws_key_detected(self):
        result = scan_pii("Key: AKIAIOSFODNN7EXAMPLE")
        types = {m.entity_type for m in result.matches}
        assert "AWS_KEY" in types

    def test_aws_key_risk_high(self):
        result = scan_pii("AKIAIOSFODNN7EXAMPLE")
        assert result.risk_level == "high"


# ── JWT detection ──────────────────────────────────────────────────────────────

class TestJwtDetection:
    def test_jwt_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = scan_pii(f"Token: {jwt}")
        types = {m.entity_type for m in result.matches}
        assert "JWT" in types

    def test_jwt_risk_high(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = scan_pii(jwt)
        assert result.risk_level == "high"


# ── IP address detection ───────────────────────────────────────────────────────

class TestIpDetection:
    def test_ip_detected(self):
        result = scan_pii("Server at 192.168.1.100")
        types = {m.entity_type for m in result.matches}
        assert "IP_ADDRESS" in types

    def test_ip_risk_low(self):
        result = scan_pii("192.168.1.1")
        assert result.risk_level == "low"


# ── Critical risk (multiple high-sensitivity) ──────────────────────────────────

class TestCriticalRisk:
    def test_two_ssns_gives_critical(self):
        result = scan_pii("SSN1: 123-45-6789 and SSN2: 987-65-4321")
        assert result.risk_level == "critical"

    def test_ssn_and_credit_card_gives_critical(self):
        result = scan_pii("SSN: 123-45-6789  Card: 4111-1111-1111-1111")
        assert result.risk_level == "critical"


# ── Masking behaviour ──────────────────────────────────────────────────────────

class TestMasking:
    def test_short_value_masked_fully(self):
        # Email with short local part: still masked
        result = scan_pii("a@b.co")
        for m in result.matches:
            assert "***" in m.masked_value

    def test_raw_value_not_in_result(self):
        text = "admin@secret.com"
        result = scan_pii(text)
        dumped = result.model_dump_json()
        assert "admin@secret.com" not in dumped

    def test_hash_stored(self):
        text = "test@example.com"
        result = scan_pii(text)
        assert result.response_hash == _sha256(text)


# ── Ordering ───────────────────────────────────────────────────────────────────

class TestOrdering:
    def test_matches_sorted_by_position(self):
        text = "First 192.168.0.1 then user@example.com"
        result = scan_pii(text)
        starts = [m.start for m in result.matches]
        assert starts == sorted(starts)
