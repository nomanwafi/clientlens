"""Engine, registry and safety-rail tests.

These cover the accuracy contract: authorisation enforcement, request budget,
probe dependency ordering and confidence invariants.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from clientlens.core.config import ScanConfig
from clientlens.core.engine import ScanEngine
from clientlens.core.exceptions import AuthorizationRequired
from clientlens.core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from clientlens.core.registry import (
    REGISTRY,
    ProbeContext,
    ProbeMode,
    ProbePhase,
    ProbeSpec,
    run_probe,
)
from clientlens.core.target import normalize_target
from clientlens.probes.shared.http_client import HttpCaptureClient, RateLimiter


# --------------------------------------------------------------------------- #
# Rate limiter / request budget
# --------------------------------------------------------------------------- #
class TestRateLimiter:
    def test_budget_is_enforced(self):
        limiter = RateLimiter(rate_per_second=1000, max_requests=3)

        async def go():
            for _ in range(3):
                await limiter.acquire()
            with pytest.raises(Exception, match="budget exhausted"):
                await limiter.acquire()

        asyncio.run(go())

    def test_rate_is_respected(self):
        limiter = RateLimiter(rate_per_second=50, max_requests=10)

        async def go():
            start = asyncio.get_event_loop().time()
            for _ in range(3):
                await limiter.acquire()
            return asyncio.get_event_loop().time() - start

        elapsed = asyncio.run(go())
        # 3 acquires at 50/s = at least 2 intervals of 20ms.
        assert elapsed >= 0.03


class TestHttpCaptureClient:
    @respx.mock
    def test_records_redirect_chain(self):
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(302, headers={"location": "https://example.com/final"})
        )
        respx.get("https://example.com/final").mock(
            return_value=httpx.Response(
                200, text="<html>ok</html>", headers={"content-type": "text/html"}
            )
        )

        config = ScanConfig(authorized=True)

        async def go():
            async with HttpCaptureClient(config) as client:
                return await client.get("https://example.com/")

        resp = asyncio.run(go())
        assert resp.status == 200
        assert resp.final_url.endswith("/final")
        assert len(resp.redirect_chain) == 1

    @respx.mock
    def test_network_error_is_captured_not_raised(self):
        respx.get("https://example.com/").mock(side_effect=httpx.ConnectError("nope"))
        config = ScanConfig(authorized=True)

        async def go():
            async with HttpCaptureClient(config) as client:
                return await client.get("https://example.com/")

        resp = asyncio.run(go())
        assert not resp.ok
        assert "ConnectError" in resp.error


# --------------------------------------------------------------------------- #
# Authorisation
# --------------------------------------------------------------------------- #
class TestAuthorisation:
    def test_scan_refused_without_authorisation(self):
        engine = ScanEngine(ScanConfig(authorized=False))
        with pytest.raises(AuthorizationRequired):
            asyncio.run(engine.run("example.com"))

    def test_authorisation_flag_is_recorded(self):
        assert ScanConfig(authorized=True).scan_mode == "passive"
        assert ScanConfig(authorized=True, allow_active=True).scan_mode == "active"


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
class TestRegistry:
    def test_bundled_probes_are_registered(self):
        import clientlens.probes  # noqa: F401

        assert len(REGISTRY.ids()) >= 20
        assert "shared.capture" in REGISTRY.ids()
        assert "security.headers" in REGISTRY.ids()
        assert "marketing.seo.meta" in REGISTRY.ids()

    def test_active_probes_excluded_by_default(self):
        import clientlens.probes  # noqa: F401

        specs = REGISTRY.select(allow_active=False)
        assert all(s.mode is not ProbeMode.ACTIVE for s in specs)

    def test_active_probes_included_when_enabled(self):
        import clientlens.probes  # noqa: F401

        specs = REGISTRY.select(allow_active=True)
        assert any(s.mode is ProbeMode.ACTIVE for s in specs)

    def test_phase_ordering(self):
        import clientlens.probes  # noqa: F401

        specs = REGISTRY.select(allow_active=True)
        phases = [s.phase for s in specs]
        order = {ProbePhase.CAPTURE: 0, ProbePhase.ANALYSE: 1, ProbePhase.ACTIVE: 2}
        assert phases == sorted(phases, key=lambda p: order[p])

    def test_include_exclude_filters(self):
        import clientlens.probes  # noqa: F401

        only_sec = REGISTRY.select(include=["security"], allow_active=True)
        assert only_sec
        assert all(s.id.startswith("security.") for s in only_sec)

        no_sec = REGISTRY.select(exclude=["security"], allow_active=True)
        assert no_sec
        assert all(not s.id.startswith("security.") for s in no_sec)

    def test_duplicate_id_rejected(self):
        from clientlens.core.registry import Registry

        reg = Registry()

        async def fn(ctx):
            return []

        spec = ProbeSpec(id="x.y", fn=fn, category=Category.SECURITY)
        reg.add(spec)
        with pytest.raises(ValueError, match="duplicate"):
            reg.add(spec)


# --------------------------------------------------------------------------- #
# Probe execution
# --------------------------------------------------------------------------- #
class TestProbeExecution:
    def test_probe_missing_facts_is_skipped_not_crashed(self):
        async def fn(ctx):
            return []

        spec = ProbeSpec(
            id="t.need",
            fn=fn,
            category=Category.SECURITY,
            requires=("http_response",),
        )
        ctx = ProbeContext(target=normalize_target("example.com"), config=ScanConfig())
        result = asyncio.run(run_probe(spec, ctx))
        assert result.status == "skipped"
        assert "missing required facts" in result.error

    def test_probe_exception_is_captured(self):
        async def fn(ctx):
            raise RuntimeError("boom")

        spec = ProbeSpec(id="t.boom", fn=fn, category=Category.SECURITY)
        ctx = ProbeContext(target=normalize_target("example.com"), config=ScanConfig())
        result = asyncio.run(run_probe(spec, ctx))
        assert result.status == "error"
        assert "RuntimeError" in result.error

    def test_probe_timeout_is_captured(self):
        async def fn(ctx):
            await asyncio.sleep(5)
            return []

        spec = ProbeSpec(id="t.slow", fn=fn, category=Category.SECURITY, timeout_s=0.05)
        ctx = ProbeContext(target=normalize_target("example.com"), config=ScanConfig())
        result = asyncio.run(run_probe(spec, ctx))
        assert result.status == "error"
        assert "timed out" in result.error

    def test_findings_are_tagged_with_probe_and_target(self):
        async def fn(ctx):
            return [
                Finding(
                    id="t.f",
                    title="t",
                    category=Category.SECURITY,
                    kind=FindingKind.OBSERVATION,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.text("x"),
                )
            ]

        spec = ProbeSpec(id="t.tag", fn=fn, category=Category.SECURITY)
        ctx = ProbeContext(target=normalize_target("example.com"), config=ScanConfig())
        result = asyncio.run(run_probe(spec, ctx))
        assert result.status == "ok"
        assert result.findings[0].probe_id == "t.tag"
        assert result.findings[0].target == "example.com"


# --------------------------------------------------------------------------- #
# Confidence invariants
# --------------------------------------------------------------------------- #
class TestConfidenceContract:
    def test_vulnerability_vector_cannot_be_confirmed(self):
        f = Finding(
            id="a.b",
            title="t",
            category=Category.SECURITY,
            kind=FindingKind.VULNERABILITY_VECTOR,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.text("x"),
        )
        assert f.confidence is Confidence.LIKELY

    def test_evidence_is_always_present(self):
        f = Finding(
            id="a.b",
            title="t",
            category=Category.SECURITY,
            kind=FindingKind.OBSERVATION,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.none("nothing"),
        )
        assert f.evidence.raw
        assert f.evidence.type.value == "not_applicable"

    def test_risk_score_respects_confidence(self):
        from clientlens.core.models import ScanResult

        def make(conf):
            return ScanResult(
                target=normalize_target("example.com"),
                scan_id="",
                started_at="2026-01-01T00:00:00+00:00",
                findings=[
                    Finding(
                        id="x",
                        title="t",
                        category=Category.SECURITY,
                        kind=FindingKind.MISCONFIGURATION,
                        severity=Severity.CRITICAL,
                        confidence=conf,
                        evidence=Evidence.text("x"),
                    )
                ],
            )

        assert make(Confidence.CONFIRMED).risk_score > make(Confidence.LIKELY).risk_score
        assert make(Confidence.LIKELY).risk_score > make(Confidence.NEEDS_REVIEW).risk_score


# --------------------------------------------------------------------------- #
# Scan result serialisation
# --------------------------------------------------------------------------- #
class TestSerialisation:
    def test_scan_result_to_json_round_trips(self):
        import json

        from clientlens.core.models import ScanResult

        result = ScanResult(
            target=normalize_target("example.com"),
            scan_id="",
            started_at="2026-01-01T00:00:00+00:00",
            findings=[
                Finding(
                    id="a.b",
                    title="t",
                    category=Category.MARKETING,
                    kind=FindingKind.STRENGTH,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_headers({"x": "y"}, source="GET /"),
                    tags=["seo"],
                )
            ],
        )
        payload = json.loads(result.to_json())
        assert payload["target"]["domain"] == "example.com"
        assert payload["findings"][0]["category"] == "marketing"
        assert payload["findings"][0]["evidence"]["type"] == "http_headers"
        assert payload["counts"]["findings"] == 1


# --------------------------------------------------------------------------- #
# Report renderers
# --------------------------------------------------------------------------- #
class TestReportRenderers:
    def _result(self):
        from clientlens.core.models import ScanResult

        return ScanResult(
            target=normalize_target("https://example.com/"),
            scan_id="",
            started_at="2026-01-01T00:00:00+00:00",
            findings=[
                Finding(
                    id="sec.x",
                    title="Missing header",
                    category=Category.SECURITY,
                    kind=FindingKind.MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_headers({"server": "nginx"}, source="GET /"),
                    reasoning="Because it matters.",
                    remediation="Add the header.",
                    tags=["headers"],
                ),
                Finding(
                    id="mkt.y",
                    title="Needs review thing",
                    category=Category.MARKETING,
                    kind=FindingKind.GAP,
                    severity=Severity.INFO,
                    confidence=Confidence.NEEDS_REVIEW,
                    evidence=Evidence.text("not tested"),
                ),
            ],
            coverage_gaps=["Something not tested"],
        )

    def test_html_renders(self):
        from clientlens.report.html_export import render_html

        html = render_html(self._result())
        assert "Missing header" in html
        assert "Needs manual review" in html
        assert "What this scan did" in html
        assert 'class="conf confirmed"' in html
        assert 'class="conf needs_review"' in html

    def test_json_export(self):
        from clientlens.report.json_export import to_dict

        payload = to_dict(self._result())
        assert payload["schema"]["name"] == "clientlens.scan"
        assert "confirmed" in payload["schema"]["confidence_levels"]

    def test_console_renders(self):
        from io import StringIO

        from rich.console import Console

        from clientlens.report.console import render

        buffer = StringIO()
        console = Console(file=buffer, width=100, force_terminal=True)
        render(self._result(), console, show_evidence=True)
        out = buffer.getvalue()
        assert "Missing header" in out
        assert "Needs manual review" in out
        assert "NOT tested" in out or "did NOT test" in out

    def test_pdf_renders(self):
        pytest.importorskip("xhtml2pdf")
        from clientlens.report.pdf_export import render_pdf

        pdf = render_pdf(self._result())
        assert pdf[:4] == b"%PDF"
        assert len(pdf) > 1000
