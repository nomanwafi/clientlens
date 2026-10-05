"""Tests for the deep-scan probes and the new CLI features.

Each probe is exercised against a synthetic captured input so a regression in
the rule is caught immediately. Network-touching probes are tested against a
fake client, never the live internet.
"""

from __future__ import annotations

import asyncio

from clientlens.core.config import ScanConfig
from clientlens.core.models import (
    FindingKind,
    ScanResult,
    ScanTarget,
    Severity,
)
from clientlens.core.registry import ProbeContext
from clientlens.probes.shared.dns_client import DnsAnswer
from clientlens.probes.shared.html import parse_html
from clientlens.probes.shared.http_client import FetchedResponse, RateLimiter


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def make_ctx(*, html: str = "<html></html>", headers: dict | None = None, status: int = 200):
    target = ScanTarget(
        raw="https://example.com",
        domain="example.com",
        apex="example.com",
        scheme="https",
        base_url="https://example.com",
    )
    resp = FetchedResponse(
        url="https://example.com/",
        final_url="https://example.com/",
        status=status,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        body=html,
        elapsed_ms=120,
    )
    ctx = ProbeContext(target=target, config=ScanConfig(authorized=True), facts={})
    ctx.set_fact("http_response", resp)
    ctx.set_fact("html", parse_html("https://example.com/", "https://example.com/", html))
    return ctx


def by_id(findings):
    return {f.id: f for f in findings}


def _run(fn, ctx):
    return asyncio.run(fn(ctx))


# --------------------------------------------------------------------------- #
# CSP deep analysis
# --------------------------------------------------------------------------- #
class TestCspDeep:
    def test_report_only_mode_is_flagged(self):
        from clientlens.probes.security.csp_deep import check_csp_deep

        ctx = make_ctx(headers={"content-security-policy-report-only": "default-src 'self'"})
        findings = by_id(_run(check_csp_deep, ctx))
        assert "security.csp.report_only_mode" in findings
        assert findings["security.csp.report_only_mode"].kind is FindingKind.MISCONFIGURATION

    def test_unsafe_inline_and_eval_are_flagged(self):
        from clientlens.probes.security.csp_deep import check_csp_deep

        ctx = make_ctx(
            headers={
                "content-security-policy": (
                    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                    "object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'"
                )
            }
        )
        findings = by_id(_run(check_csp_deep, ctx))
        assert "security.csp.unsafe_directives" in findings
        f = findings["security.csp.unsafe_directives"]
        assert "'unsafe-inline'" in f.reasoning or "unsafe-inline" in f.evidence.raw

    def test_wildcard_sources_are_flagged(self):
        from clientlens.probes.security.csp_deep import check_csp_deep

        ctx = make_ctx(headers={"content-security-policy": "default-src *"})
        findings = by_id(_run(check_csp_deep, ctx))
        assert "security.csp.wildcard_sources" in findings

    def test_missing_hardening_directives_are_flagged(self):
        from clientlens.probes.security.csp_deep import check_csp_deep

        ctx = make_ctx(headers={"content-security-policy": "default-src 'self'"})
        findings = by_id(_run(check_csp_deep, ctx))
        assert "security.csp.missing_directives" in findings
        f = findings["security.csp.missing_directives"]
        assert "object-src" in f.reasoning
        assert "frame-ancestors" in f.reasoning

    def test_well_configured_csp_is_a_strength(self):
        from clientlens.probes.security.csp_deep import check_csp_deep

        ctx = make_ctx(
            headers={
                "content-security-policy": (
                    "default-src 'self'; script-src 'self'; object-src 'none'; "
                    "base-uri 'self'; frame-ancestors 'self'; form-action 'self'"
                )
            }
        )
        findings = by_id(_run(check_csp_deep, ctx))
        assert "security.csp.well_configured" in findings
        assert findings["security.csp.well_configured"].kind is FindingKind.STRENGTH

    def test_no_csp_produces_no_duplicate_finding(self):
        from clientlens.probes.security.csp_deep import check_csp_deep

        ctx = make_ctx(headers={})
        findings = _run(check_csp_deep, ctx)
        assert findings == []


# --------------------------------------------------------------------------- #
# Accessibility
# --------------------------------------------------------------------------- #
class TestAccessibility:
    def test_missing_lang_is_flagged(self):
        from clientlens.probes.marketing.accessibility import check_accessibility

        html = "<html><head></head><body></body></html>"
        findings = by_id(_run(check_accessibility, make_ctx(html=html)))
        assert "marketing.a11y.lang_missing" in findings

    def test_lang_present_is_a_strength(self):
        from clientlens.probes.marketing.accessibility import check_accessibility

        html = '<html lang="en"><head></head><body></body></html>'
        findings = by_id(_run(check_accessibility, make_ctx(html=html)))
        assert "marketing.a11y.lang_present" in findings
        assert findings["marketing.a11y.lang_present"].kind is FindingKind.STRENGTH

    def test_missing_viewport_is_flagged(self):
        from clientlens.probes.marketing.accessibility import check_accessibility

        html = "<html><head></head><body></body></html>"
        findings = by_id(_run(check_accessibility, make_ctx(html=html)))
        assert "marketing.a11y.viewport_missing" in findings

    def test_zoom_disabled_viewport_is_flagged(self):
        from clientlens.probes.marketing.accessibility import check_accessibility

        html = (
            '<html><head><meta name="viewport" '
            'content="width=device-width, user-scalable=no"></head>'
            "<body></body></html>"
        )
        findings = by_id(_run(check_accessibility, make_ctx(html=html)))
        assert "marketing.a11y.zoom_disabled" in findings

    def test_images_without_alt_are_counted(self):
        from clientlens.probes.marketing.accessibility import check_accessibility

        html = (
            "<html><head></head><body>"
            '<img src="a.png"><img src="b.png" alt="ok"><img src="c.png">'
            "</body></html>"
        )
        findings = by_id(_run(check_accessibility, make_ctx(html=html)))
        assert "marketing.a11y.img_alt_missing" in findings
        f = findings["marketing.a11y.img_alt_missing"]
        assert "2 of 3" in f.title

    def test_full_alt_coverage_is_a_strength(self):
        from clientlens.probes.marketing.accessibility import check_accessibility

        html = (
            "<html><head></head><body>"
            '<img src="a.png" alt=""><img src="b.png" alt="ok">'
            "</body></html>"
        )
        findings = by_id(_run(check_accessibility, make_ctx(html=html)))
        assert "marketing.a11y.img_alt_complete" in findings


# --------------------------------------------------------------------------- #
# Forms
# --------------------------------------------------------------------------- #
class TestForms:
    def test_no_forms_is_observation(self):
        from clientlens.probes.marketing.forms import check_forms

        findings = by_id(_run(check_forms, make_ctx(html="<html><body></body></html>")))
        assert "marketing.forms.none" in findings
        assert findings["marketing.forms.none"].kind is FindingKind.OBSERVATION

    def test_form_count_is_reported(self):
        from clientlens.probes.marketing.forms import check_forms

        html = (
            "<html><body>"
            '<form action="/a" method="post"><input type="text"></form>'
            '<form action="/b" method="post"><input type="text"></form>'
            "</body></html>"
        )
        findings = by_id(_run(check_forms, make_ctx(html=html)))
        assert "marketing.forms.count" in findings

    def test_get_form_with_email_is_flagged(self):
        from clientlens.probes.marketing.forms import check_forms

        html = (
            "<html><body>"
            '<form action="/subscribe" method="get">'
            '<input type="email" name="email" aria-label="Email"></form>'
            "</body></html>"
        )
        findings = by_id(_run(check_forms, make_ctx(html=html)))
        assert "marketing.forms.form_0_get_sensitive" in findings
        f = findings["marketing.forms.form_0_get_sensitive"]
        assert f.severity is Severity.MEDIUM

    def test_cross_origin_action_is_observed(self):
        from clientlens.probes.marketing.forms import check_forms

        html = (
            "<html><body>"
            '<form action="https://other.example.net/x" method="post">'
            '<input type="text" aria-label="Name"></form>'
            "</body></html>"
        )
        findings = by_id(_run(check_forms, make_ctx(html=html)))
        assert "marketing.forms.form_0_cross_origin" in findings

    def test_unlabeled_inputs_are_flagged(self):
        from clientlens.probes.marketing.forms import check_forms

        html = (
            '<html><body><form action="/x" method="post"><input type="text"></form></body></html>'
        )
        findings = by_id(_run(check_forms, make_ctx(html=html)))
        assert "marketing.forms.form_0_unlabeled" in findings

    def test_labeled_inputs_are_not_flagged(self):
        from clientlens.probes.marketing.forms import check_forms

        html = (
            "<html><body>"
            '<form action="/x" method="post">'
            '<label for="n">Name</label><input id="n" type="text">'
            "</form></body></html>"
        )
        findings = by_id(_run(check_forms, make_ctx(html=html)))
        assert "marketing.forms.form_0_unlabeled" not in findings


# --------------------------------------------------------------------------- #
# Third-party request surface
# --------------------------------------------------------------------------- #
class TestThirdParty:
    def test_no_third_party_is_a_strength(self):
        from clientlens.probes.marketing.third_party import check_third_party

        html = '<html><head><script src="/local.js"></script></head><body></body></html>'
        findings = by_id(_run(check_third_party, make_ctx(html=html)))
        assert "marketing.third_party.none" in findings
        assert findings["marketing.third_party.none"].kind is FindingKind.STRENGTH

    def test_external_origins_are_inventoried(self):
        from clientlens.probes.marketing.third_party import check_third_party

        html = (
            "<html><head>"
            '<script src="https://cdn.vendor-a.com/lib.js"></script>'
            '<script src="https://cdn.vendor-b.com/lib.js"></script>'
            "</head><body></body></html>"
        )
        findings = by_id(_run(check_third_party, make_ctx(html=html)))
        assert "marketing.third_party.inventory" in findings
        f = findings["marketing.third_party.inventory"]
        assert "2" in f.title
        assert "cdn.vendor-a.com" in f.evidence.raw

    def test_script_origins_are_exposure(self):
        from clientlens.probes.marketing.third_party import check_third_party

        html = (
            '<html><head><script src="https://evil-cdn.com/x.js"></script></head>'
            "<body></body></html>"
        )
        findings = by_id(_run(check_third_party, make_ctx(html=html)))
        assert "marketing.third_party.script_origins" in findings
        assert findings["marketing.third_party.script_origins"].kind is FindingKind.EXPOSURE

    def test_same_origin_subdomain_is_not_third_party(self):
        from clientlens.probes.marketing.third_party import check_third_party

        html = (
            '<html><head><script src="https://static.example.com/lib.js"></script></head>'
            "<body></body></html>"
        )
        findings = by_id(_run(check_third_party, make_ctx(html=html)))
        assert "marketing.third_party.none" in findings

    def test_iframe_origins_are_observed(self):
        from clientlens.probes.marketing.third_party import check_third_party

        html = '<html><body><iframe src="https://www.youtube.com/embed/x"></iframe></body></html>'
        findings = by_id(_run(check_third_party, make_ctx(html=html)))
        assert "marketing.third_party.iframes" in findings


# --------------------------------------------------------------------------- #
# PWA & icons
# --------------------------------------------------------------------------- #
class TestPwa:
    def test_manifest_missing_is_observation(self):
        from clientlens.probes.marketing.pwa import check_pwa

        findings = by_id(_run(check_pwa, make_ctx(html="<html><head></head><body></body></html>")))
        assert "marketing.pwa.manifest_missing" in findings

    def test_manifest_present_is_strength(self):
        from clientlens.probes.marketing.pwa import check_pwa

        html = '<html><head><link rel="manifest" href="/manifest.webmanifest"></head><body></body></html>'
        findings = by_id(_run(check_pwa, make_ctx(html=html)))
        assert "marketing.pwa.manifest_present" in findings
        assert findings["marketing.pwa.manifest_present"].kind is FindingKind.STRENGTH

    def test_no_favicon_is_flagged(self):
        from clientlens.probes.marketing.pwa import check_pwa

        findings = by_id(_run(check_pwa, make_ctx(html="<html><head></head><body></body></html>")))
        assert "marketing.pwa.no_icon" in findings

    def test_apple_touch_icon_coverage_noted(self):
        from clientlens.probes.marketing.pwa import check_pwa

        html = (
            "<html><head>"
            '<link rel="icon" href="/favicon.ico">'
            '<link rel="apple-touch-icon" href="/apple-touch-icon.png">'
            "</head><body></body></html>"
        )
        findings = by_id(_run(check_pwa, make_ctx(html=html)))
        assert "marketing.pwa.icons_present" in findings
        f = findings["marketing.pwa.icons_present"]
        assert "apple-touch-icon" in f.title

    def test_service_worker_hint_detected(self):
        from clientlens.probes.marketing.pwa import check_pwa

        html = (
            "<html><head></head><body>"
            "<script>navigator.serviceWorker.register('/sw.js')</script>"
            "</body></html>"
        )
        findings = by_id(_run(check_pwa, make_ctx(html=html)))
        assert "marketing.pwa.service_worker" in findings

    def test_theme_color_noted(self):
        from clientlens.probes.marketing.pwa import check_pwa

        html = '<html><head><meta name="theme-color" content="#0a0a0a"></head><body></body></html>'
        findings = by_id(_run(check_pwa, make_ctx(html=html)))
        assert "marketing.pwa.theme_color" in findings


# --------------------------------------------------------------------------- #
# DNSSEC (DNS lookups monkeypatched)
# --------------------------------------------------------------------------- #
class TestDnssec:
    def _patch(self, monkeypatch, *, dnskey: bool, ds: bool):
        from clientlens.probes.security import dns_deep

        async def fake_resolve_record(name, rtype):
            if rtype == "DNSKEY":
                return DnsAnswer(name=name, rtype=rtype, values=["key1"] if dnskey else [])
            return DnsAnswer(name=name, rtype=rtype, values=["ds1"] if ds else [])

        monkeypatch.setattr(dns_deep, "resolve_record", fake_resolve_record)

    def test_signed_zone_is_strength(self, monkeypatch):
        from clientlens.probes.security.dns_deep import check_dnssec

        self._patch(monkeypatch, dnskey=True, ds=True)
        findings = by_id(_run(check_dnssec, make_ctx()))
        assert "security.dnssec.signed" in findings
        assert findings["security.dnssec.signed"].kind is FindingKind.STRENGTH

    def test_signed_but_no_ds_at_parent(self, monkeypatch):
        from clientlens.probes.security.dns_deep import check_dnssec

        self._patch(monkeypatch, dnskey=True, ds=False)
        findings = by_id(_run(check_dnssec, make_ctx()))
        assert "security.dnssec.unsigned_at_parent" in findings

    def test_unsigned_zone(self, monkeypatch):
        from clientlens.probes.security.dns_deep import check_dnssec

        self._patch(monkeypatch, dnskey=False, ds=False)
        findings = by_id(_run(check_dnssec, make_ctx()))
        assert "security.dnssec.unsigned" in findings


# --------------------------------------------------------------------------- #
# www / non-www canonicalisation
# --------------------------------------------------------------------------- #
class FakeHttpClient:
    """Minimal stand-in for HttpCaptureClient used by www_redirect."""

    def __init__(self, responses: dict[str, FetchedResponse]):
        self._responses = responses
        self.limiter = RateLimiter(rate_per_second=1000, max_requests=50)

    async def get(self, url: str, follow: bool = True) -> FetchedResponse:
        return self._responses.get(
            url,
            FetchedResponse(
                url=url, final_url=url, status=0, headers={}, body="", elapsed_ms=1, error="x"
            ),
        )


class TestWwwRedirect:
    def _ctx(self, responses: dict[str, FetchedResponse]):
        ctx = make_ctx()
        ctx.http_client = FakeHttpClient(responses)
        return ctx

    def _patch_dns(self, monkeypatch, other_ips: list[str]):
        from clientlens.probes.shared import dns_client

        async def fake_resolve_a(name: str) -> list[str]:
            return other_ips if name.startswith("www.") else ["192.0.2.1"]

        monkeypatch.setattr(dns_client, "resolve_a", fake_resolve_a)

    def test_no_dns_for_www(self, monkeypatch):
        from clientlens.probes.security.dns_deep import check_www_redirect

        self._patch_dns(monkeypatch, other_ips=[])
        findings = by_id(_run(check_www_redirect, self._ctx({})))
        assert "security.www.no_dns" in findings

    def test_canonicalised_redirect_is_strength(self, monkeypatch):
        from clientlens.probes.security.dns_deep import check_www_redirect

        self._patch_dns(monkeypatch, other_ips=["192.0.2.2"])
        resp = FetchedResponse(
            url="https://www.example.com/",
            final_url="https://example.com/",
            status=200,
            headers={"content-type": "text/html"},
            body="<html></html>",
            elapsed_ms=50,
        )
        findings = by_id(_run(check_www_redirect, self._ctx({"https://www.example.com/": resp})))
        assert "security.www.canonicalised" in findings
        assert findings["security.www.canonicalised"].kind is FindingKind.STRENGTH

    def test_duplicate_content_is_flagged(self, monkeypatch):
        from clientlens.probes.security.dns_deep import check_www_redirect

        self._patch_dns(monkeypatch, other_ips=["192.0.2.2"])
        resp = FetchedResponse(
            url="https://www.example.com/",
            final_url="https://www.example.com/",
            status=200,
            headers={"content-type": "text/html"},
            body="<html></html>",
            elapsed_ms=50,
        )
        findings = by_id(_run(check_www_redirect, self._ctx({"https://www.example.com/": resp})))
        assert "security.www.duplicate_content" in findings


# --------------------------------------------------------------------------- #
# Preset selection
# --------------------------------------------------------------------------- #
class TestPresetSelection:
    def _ids(self, preset: str, active: bool = False) -> set[str]:
        from clientlens.core.engine import ScanEngine

        cfg = ScanConfig(authorized=True, preset=preset, allow_active=active)
        return {s.id for s in ScanEngine(cfg)._select_specs()}

    def test_all_probes_are_registered(self):
        import clientlens.probes  # noqa: F401
        from clientlens.core.registry import REGISTRY

        assert len(REGISTRY.ids()) >= 33

    def test_quick_is_the_smallest(self):
        quick = self._ids("quick", active=True)
        standard = self._ids("standard", active=True)
        deep = self._ids("deep", active=True)
        assert len(quick) < len(standard) < len(deep)

    def test_quick_excludes_deep_only_probes(self):
        quick = self._ids("quick")
        assert "security.transport.methods" not in quick
        assert "security.dns.dnssec" not in quick
        assert "marketing.third_party" not in quick
        assert "marketing.pwa" not in quick

    def test_standard_includes_core_but_not_deep_extras(self):
        standard = self._ids("standard")
        assert "security.headers" in standard
        assert "marketing.seo.meta" in standard
        assert "security.headers.csp_deep" not in standard
        assert "marketing.accessibility" not in standard

    def test_deep_includes_everything(self):
        deep = self._ids("deep", active=True)
        for pid in (
            "security.transport.methods",
            "security.transport.http_versions",
            "security.dns.dnssec",
            "security.dns.www_redirect",
            "security.headers.csp_deep",
            "marketing.accessibility",
            "marketing.forms",
            "marketing.third_party",
            "marketing.pwa",
        ):
            assert pid in deep, pid

    def test_explicit_include_overrides_preset(self):
        from clientlens.core.engine import ScanEngine

        cfg = ScanConfig(
            authorized=True,
            preset="quick",
            include_probes=["security.headers"],
        )
        ids = {s.id for s in ScanEngine(cfg)._select_specs()}
        assert "security.headers" in ids
        # Prefix semantics: only security.headers* is selected.
        assert all(i.startswith("security.headers") for i in ids)
        assert "security.tls" not in ids


# --------------------------------------------------------------------------- #
# CSV export
# --------------------------------------------------------------------------- #
class TestCsvExport:
    def _result(self) -> ScanResult:
        return ScanResult(
            target=ScanTarget(
                raw="https://example.com",
                domain="example.com",
                apex="example.com",
                scheme="https",
                base_url="https://example.com",
            ),
            scan_id="",
            started_at="2026-01-01T00:00:00+00:00",
            findings=[],
        )

    def test_csv_rows_contain_all_columns(self):
        from clientlens.core.models import Category, Confidence, Evidence, Finding
        from clientlens.report.csv_export import COLUMNS, to_csv_rows

        result = self._result()
        result.findings.append(
            Finding(
                id="sec.x",
                title="Test finding",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text("ev", source="GET /"),
                reasoning="Because.",
                remediation="Do this.",
                tags=["headers"],
            )
        )
        rows = to_csv_rows(result)
        assert len(rows) == 1
        assert list(rows[0].keys()) == COLUMNS
        assert rows[0]["id"] == "sec.x"
        assert rows[0]["severity"] == "medium"
        assert rows[0]["tags"] == "headers"

    def test_write_csv_round_trips(self, tmp_path):
        import csv

        from clientlens.core.models import Category, Confidence, Evidence, Finding
        from clientlens.report.csv_export import write_csv

        result = self._result()
        result.findings.append(
            Finding(
                id="sec.y",
                title="Multi\nline\ntitle",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text("ev"),
            )
        )
        path = write_csv(result, tmp_path / "out.csv")
        with path.open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        # One row per finding; embedded newlines never split a row.
        assert len(rows) == 1
        assert rows[0]["id"] == "sec.y"
        assert rows[0]["title"] == "Multi line title"
