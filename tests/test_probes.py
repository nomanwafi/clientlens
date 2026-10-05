"""Probe tests driven by captured fixtures.

Each probe is tested against a known input so a regression in a rule is caught
immediately. The rule being tested is always the *assertion*, never a
re-implementation of the probe.
"""

from __future__ import annotations

import pytest

from clientlens.core.config import ScanConfig
from clientlens.core.models import (
    Confidence,
    FindingKind,
    ScanTarget,
    Severity,
)
from clientlens.core.registry import ProbeContext
from clientlens.probes.shared.html import parse_html
from clientlens.probes.shared.http_client import FetchedResponse


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


# --------------------------------------------------------------------------- #
# Security headers
# --------------------------------------------------------------------------- #
class TestSecurityHeaders:
    def test_missing_headers_are_reported_as_confirmed(self):
        from clientlens.probes.security.headers import check_security_headers

        ctx = make_ctx(headers={"content-type": "text/html"})
        findings = by_id(_run(check_security_headers, ctx))

        assert "security.headers.strict_transport_security_missing" in findings
        f = findings["security.headers.strict_transport_security_missing"]
        assert f.confidence is Confidence.CONFIRMED
        assert f.kind is FindingKind.MISCONFIGURATION
        assert f.evidence.raw  # evidence present

    def test_present_header_is_a_strength(self):
        from clientlens.probes.security.headers import check_security_headers

        ctx = make_ctx(
            headers={
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "x-content-type-options": "nosniff",
            }
        )
        findings = by_id(_run(check_security_headers, ctx))
        assert "security.headers.strict_transport_security_present" in findings
        assert findings["security.headers.strict_transport_security_present"].kind is FindingKind.STRENGTH

    def test_ineffective_csp_is_flagged(self):
        from clientlens.probes.security.headers import check_security_headers

        ctx = make_ctx(
            headers={"content-security-policy": "default-src *; script-src 'unsafe-inline'"}
        )
        findings = by_id(_run(check_security_headers, ctx))
        assert "security.headers.content_security_policy_ineffective" in findings

    def test_server_banner_disclosure(self):
        from clientlens.probes.security.headers import check_security_headers

        ctx = make_ctx(headers={"server": "Apache/2.4.49", "x-powered-by": "PHP/7.4"})
        findings = by_id(_run(check_security_headers, ctx))
        assert "security.headers.server_disclosed" in findings
        assert "security.headers.x_powered_by_disclosed" in findings

    def test_absence_is_not_reported_as_present(self):
        from clientlens.probes.security.headers import check_security_headers

        ctx = make_ctx(headers={})
        findings = by_id(_run(check_security_headers, ctx))
        # Nothing must claim a header is present when it is not.
        for fid, _f in findings.items():
            if fid.endswith("_present"):
                pytest.fail(f"{fid} reported present with empty headers")


# --------------------------------------------------------------------------- #
# Cookies
# --------------------------------------------------------------------------- #
class TestCookies:
    def test_session_cookie_without_flags(self):
        from clientlens.probes.security.cookies import check_cookies

        ctx = make_ctx(
            headers={"set-cookie": "sessionid=abc123; Path=/; HttpOnly"}
        )
        findings = by_id(_run(check_cookies, ctx))
        assert any("insecure" in k for k in findings)
        # HttpOnly is present, so no_httponly must NOT be reported.
        assert not any("no_httponly" in k for k in findings)

    def test_secure_httponly_samesite_cookie_is_clean(self):
        from clientlens.probes.security.cookies import check_cookies

        ctx = make_ctx(
            headers={
                "set-cookie": "sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
            }
        )
        findings = _run(check_cookies, ctx)
        problems = [f for f in findings if f.kind is FindingKind.MISCONFIGURATION]
        assert problems == []

    def test_no_cookies_is_observation_not_failure(self):
        from clientlens.probes.security.cookies import check_cookies

        ctx = make_ctx(headers={})
        findings = by_id(_run(check_cookies, ctx))
        assert "security.cookies.none_set" in findings
        assert findings["security.cookies.none_set"].kind is FindingKind.OBSERVATION

    def test_tracker_cookie_is_observed(self):
        from clientlens.probes.security.cookies import check_cookies

        ctx = make_ctx(headers={"set-cookie": "_ga=GA1.2.111; Path=/"})
        findings = by_id(_run(check_cookies, ctx))
        assert any("tracker" in k for k in findings)


# --------------------------------------------------------------------------- #
# Mixed content
# --------------------------------------------------------------------------- #
class TestMixedContent:
    def test_active_mixed_content_detected(self):
        from clientlens.probes.security.mixed_content import check_mixed_content

        html = """
        <html><head>
          <script src="http://evil.example/x.js"></script>
          <link rel="stylesheet" href="http://cdn.example/style.css">
        </head><body></body></html>
        """
        findings = by_id(_run(check_mixed_content, make_ctx(html=html)))
        assert "security.mixed_content.active" in findings
        assert findings["security.mixed_content.active"].severity is Severity.HIGH

    def test_passive_mixed_content_detected(self):
        from clientlens.probes.security.mixed_content import check_mixed_content

        html = '<html><body><img src="http://img.example/a.png"></body></html>'
        findings = by_id(_run(check_mixed_content, make_ctx(html=html)))
        assert "security.mixed_content.passive" in findings
        assert findings["security.mixed_content.passive"].severity is Severity.LOW

    def test_https_only_is_strength(self):
        from clientlens.probes.security.mixed_content import check_mixed_content

        html = '<html><body><img src="https://img.example/a.png"></body></html>'
        findings = by_id(_run(check_mixed_content, make_ctx(html=html)))
        assert "security.mixed_content.none" in findings
        assert findings["security.mixed_content.none"].kind is FindingKind.STRENGTH


# --------------------------------------------------------------------------- #
# SEO meta
# --------------------------------------------------------------------------- #
class TestSeoMeta:
    def test_title_and_description_missing(self):
        from clientlens.probes.marketing.meta_seo import check_meta_seo

        findings = by_id(_run(check_meta_seo, make_ctx(html="<html><head></head></html>")))
        assert "marketing.seo.title_missing" in findings
        assert "marketing.seo.description_missing" in findings
        assert findings["marketing.seo.title_missing"].severity is Severity.HIGH

    def test_noindex_is_high_severity(self):
        from clientlens.probes.marketing.meta_seo import check_meta_seo

        html = """
        <html><head>
          <title>Some page title here for testing</title>
          <meta name="robots" content="noindex, nofollow">
        </head><body><h1>Head</h1></body></html>
        """
        findings = by_id(_run(check_meta_seo, make_ctx(html=html)))
        assert "marketing.seo.robots_blocking" in findings
        assert findings["marketing.seo.robots_blocking"].severity is Severity.HIGH

    def test_single_h1_is_strength(self):
        from clientlens.probes.marketing.meta_seo import check_meta_seo

        html = """
        <html><head><title>Test Title For The Page</title></head>
        <body><h1>Main heading</h1></body></html>
        """
        findings = by_id(_run(check_meta_seo, make_ctx(html=html)))
        assert "marketing.seo.h1_present" in findings

    def test_multiple_h1_is_flagged(self):
        from clientlens.probes.marketing.meta_seo import check_meta_seo

        html = """
        <html><head><title>Test Title For The Page</title></head>
        <body><h1>One</h1><h1>Two</h1></body></html>
        """
        findings = by_id(_run(check_meta_seo, make_ctx(html=html)))
        assert "marketing.seo.h1_multiple" in findings


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
class TestSchema:
    def test_absent_schema(self):
        from clientlens.probes.marketing.schema import check_schema

        findings = by_id(_run(check_schema, make_ctx(html="<html></html>")))
        assert "marketing.schema.absent" in findings
        assert findings["marketing.schema.absent"].severity is Severity.MEDIUM

    def test_valid_jsonld_inventory(self):
        from clientlens.probes.marketing.schema import check_schema

        html = """
        <html><head>
        <script type="application/ld+json">
        {"@context":"https://schema.org","@type":"Organization","name":"Acme"}
        </script>
        <script type="application/ld+json">
        {"@context":"https://schema.org","@type":"WebSite","name":"Acme"}
        </script>
        </head><body></body></html>
        """
        findings = by_id(_run(check_schema, make_ctx(html=html)))
        assert "marketing.schema.inventory" in findings
        assert "marketing.schema.high_value_types" in findings
        # Organization present → no organization_missing finding.
        assert "marketing.schema.organization_missing" not in findings

    def test_invalid_jsonld_is_reported(self):
        from clientlens.probes.marketing.schema import check_schema

        html = """
        <html><head>
        <script type="application/ld+json">{not valid json</script>
        </head><body></body></html>
        """
        findings = by_id(_run(check_schema, make_ctx(html=html)))
        assert "marketing.schema.block_0_invalid_json" in findings


# --------------------------------------------------------------------------- #
# Social meta
# --------------------------------------------------------------------------- #
class TestSocialMeta:
    def test_no_og_tags(self):
        from clientlens.probes.marketing.social_meta import check_social_meta

        findings = by_id(_run(check_social_meta, make_ctx(html="<html><head></head></html>")))
        assert "marketing.social.og_absent" in findings

    def test_full_og_and_twitter(self):
        from clientlens.probes.marketing.social_meta import check_social_meta

        html = """
        <html><head>
        <meta property="og:title" content="T">
        <meta property="og:description" content="D">
        <meta property="og:image" content="https://x/i.png">
        <meta property="og:url" content="https://x/">
        <meta property="og:type" content="website">
        <meta name="twitter:card" content="summary_large_image">
        </head><body></body></html>
        """
        findings = by_id(_run(check_social_meta, make_ctx(html=html)))
        assert "marketing.social.og_absent" not in findings
        assert "marketing.social.twitter_absent" not in findings
        assert "marketing.social.og_image_present" in findings


# --------------------------------------------------------------------------- #
# Redirect chain
# --------------------------------------------------------------------------- #
class TestRedirectChain:
    def test_plaintext_hop_flagged(self):
        from clientlens.probes.security.redirects import check_redirect_chain

        ctx = make_ctx()
        resp = ctx.facts["http_response"]
        resp.url = "http://example.com/"
        resp.redirect_chain = ["301 -> https://example.com/"]
        findings = by_id(_run(check_redirect_chain, ctx))
        assert "security.redirects.plaintext_hop" in findings
        assert findings["security.redirects.plaintext_hop"].severity is Severity.MEDIUM

    def test_no_redirects(self):
        from clientlens.probes.security.redirects import check_redirect_chain

        findings = by_id(_run(check_redirect_chain, make_ctx()))
        assert "security.redirects.none" in findings


# --------------------------------------------------------------------------- #
# Tracking fingerprints
# --------------------------------------------------------------------------- #
class TestTrackingFingerprints:
    def test_ga4_detected_from_script_src(self):
        from clientlens.probes.shared import fingerprints

        hits = fingerprints.match_trackers(
            script_srcs=["https://googletagmanager.com/gtag/js?id=G-ABC123"],
            inline_scripts=[],
            cookie_names=[],
        )
        assert any(h.id == "ga4" for h in hits)

    def test_pixel_detected_from_inline(self):
        from clientlens.probes.shared import fingerprints

        hits = fingerprints.match_trackers(
            script_srcs=[],
            inline_scripts=["fbq('init', '123456789'); fbq('track', 'PageView');"],
            cookie_names=[],
        )
        assert any(h.id == "fb_pixel" for h in hits)

    def test_no_false_positive_on_empty_input(self):
        from clientlens.probes.shared import fingerprints

        hits = fingerprints.match_trackers(
            script_srcs=[], inline_scripts=[], cookie_names=[]
        )
        assert hits == []

    def test_consent_platform_detection(self):
        from clientlens.probes.shared import fingerprints

        hits = fingerprints.match_consent_platform(
            html_blob='<div id="onetrust-consent-sdk"></div>',
            script_srcs=[],
            cookie_names=["OptanonConsent"],
        )
        assert any(p.id == "onetrust" for p in hits)

    def test_tech_stack_detection(self):
        from clientlens.probes.shared import fingerprints

        hits = fingerprints.match_tech(
            html_blob='<link href="/wp-content/themes/x/style.css"><script src="/wp-includes/js/wp.js">',
            headers={"server": "nginx"},
            meta_generator="WordPress 6.4",
            cookie_names=["wp-settings-1"],
        )
        names = {h.id for h in hits}
        assert "wordpress" in names
        assert "nginx" in names


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _run(fn, ctx):
    """Run an async probe and return its findings list."""
    import asyncio

    return asyncio.run(fn(ctx))
