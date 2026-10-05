"""Core model and target tests — the accuracy contract."""

from __future__ import annotations

import pytest

from clientlens.core.exceptions import InvalidTarget
from clientlens.core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from clientlens.core.target import normalize_target


class TestFindingInvariants:
    def test_vulnerability_vector_is_never_confirmed(self):
        f = Finding(
            id="t.x",
            title="test",
            category=Category.SECURITY,
            kind=FindingKind.VULNERABILITY_VECTOR,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.text("x"),
        )
        assert f.confidence is Confidence.LIKELY

    def test_observation_can_be_confirmed(self):
        f = Finding(
            id="t.y",
            title="test",
            category=Category.SECURITY,
            kind=FindingKind.OBSERVATION,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.text("x"),
        )
        assert f.confidence is Confidence.CONFIRMED

    def test_fingerprint_is_stable(self):
        def make():
            return Finding(
                id="a.b",
                title="t",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text("raw", source="s"),
            )

        assert make().fingerprint == make().fingerprint

    def test_evidence_always_present(self):
        f = Finding(
            id="a.b",
            title="t",
            category=Category.SECURITY,
            kind=FindingKind.OBSERVATION,
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.none("nothing captured"),
        )
        assert f.evidence.raw

    def test_to_dict_round_trips_enums(self):
        f = Finding(
            id="a.b",
            title="t",
            category=Category.MARKETING,
            kind=FindingKind.GAP,
            severity=Severity.INFO,
            confidence=Confidence.NEEDS_REVIEW,
            evidence=Evidence.text("x"),
        )
        d = f.to_dict()
        assert d["category"] == "marketing"
        assert d["kind"] == "gap"
        assert d["confidence"] == "needs_review"
        assert d["evidence"]["type"] == "text"
        assert d["fingerprint"]


class TestScanResultScoring:
    def _result(self, findings):
        from clientlens.core.models import ScanResult

        return ScanResult(
            target=normalize_target("example.com"),
            scan_id="",
            started_at="2026-01-01T00:00:00+00:00",
            findings=findings,
        )

    def test_risk_score_ignores_low_confidence_inflation(self):
        strong = Finding(
            id="s1",
            title="t",
            category=Category.SECURITY,
            kind=FindingKind.MISCONFIGURATION,
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.text("x"),
        )
        weak = Finding(
            id="w1",
            title="t",
            category=Category.SECURITY,
            kind=FindingKind.MISCONFIGURATION,
            severity=Severity.CRITICAL,
            confidence=Confidence.NEEDS_REVIEW,
            evidence=Evidence.text("x"),
        )
        assert self._result([strong]).risk_score > self._result([weak]).risk_score

    def test_counts(self):
        f = Finding(
            id="a",
            title="t",
            category=Category.MARKETING,
            kind=FindingKind.STRENGTH,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.text("x"),
        )
        r = self._result([f])
        assert r.counts_by_severity["info"] == 1
        assert r.counts_by_category["marketing"] == 1
        assert len(r.strongest_points) == 1


class TestTargetParsing:
    @pytest.mark.parametrize(
        "raw,domain,apex",
        [
            ("example.com", "example.com", "example.com"),
            ("www.example.com", "www.example.com", "example.com"),
            ("https://shop.example.co.uk/path?q=1", "shop.example.co.uk", "example.co.uk"),
            ("EXAMPLE.COM.", "example.com", "example.com"),
            ("example.com:8443", "example.com", "example.com"),
        ],
    )
    def test_valid(self, raw, domain, apex):
        t = normalize_target(raw)
        assert t.domain == domain
        assert t.apex == apex

    @pytest.mark.parametrize(
        "raw",
        ["", "   ", "ftp://example.com", "not a host", "http://", "example.com;rm -rf"],
    )
    def test_invalid(self, raw):
        with pytest.raises(InvalidTarget):
            normalize_target(raw)

    def test_private_ip_rejected_by_default(self):
        with pytest.raises(InvalidTarget):
            normalize_target("127.0.0.1")

    def test_private_ip_allowed_with_flag(self):
        t = normalize_target("127.0.0.1", allow_private=True)
        assert t.domain == "127.0.0.1"

    def test_localhost_name_rejected(self):
        with pytest.raises(InvalidTarget):
            normalize_target("myhost.local")
