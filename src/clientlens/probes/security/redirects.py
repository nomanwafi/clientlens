"""Redirect chain analysis and open-redirect vector detection.

The redirect chain is a directly observed fact. Open-redirect is reported as a
*vector* (``VULNERABILITY_VECTOR``) and never as a confirmed vulnerability —
confirming it requires a manual verification step the tool cannot do honestly.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse

from ...core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from ...core.registry import ProbeContext, ProbeMode, ProbePhase, register_probe

OPEN_REDIRECT_PARAMS = ("next", "url", "redirect", "return", "continue", "dest", "destination", "r")


@register_probe(
    id="security.redirects.chain",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("http_response",),
    title="Redirect chain",
    description="Recorded redirect hops and their protocol/security implications.",
    tags=("redirects", "transport"),
)
async def check_redirect_chain(ctx: ProbeContext) -> list[Finding]:
    """Report the observed redirect chain for the homepage."""
    resp = ctx.require("http_response")
    findings: list[Finding] = []
    source = f"GET {resp.url}"

    if not resp.ok:
        return findings

    if not resp.redirect_chain:
        findings.append(
            Finding(
                id="security.redirects.none",
                title="No redirects on the homepage request",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    f"{resp.url} -> {resp.final_url} ({resp.status})", source=source
                ),
                reasoning="The homepage was served without intermediate redirects.",
                scope=f"Redirect chain of {resp.url}",
                tags=["redirects"],
            )
        )
        return findings

    chain_text = (
        f"{resp.url}\n"
        + "\n".join(f"  {hop}" for hop in resp.redirect_chain)
        + f"\n  -> {resp.final_url} ({resp.status})"
    )

    # ---- http -> https downgrade anywhere in the chain ---------------------
    downgrades = [
        hop
        for hop in resp.redirect_chain
        if hop.strip().startswith(("301", "302", "303", "307", "308")) and "http://" in hop
    ]
    # Also check the initial URL itself.
    if resp.url.startswith("http://") or downgrades:
        findings.append(
            Finding(
                id="security.redirects.plaintext_hop",
                title="Redirect chain includes a plaintext http:// hop",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(
                    chain_text, summary=f"{len(resp.redirect_chain)} hop(s)", source=source
                ),
                reasoning=(
                    "The first request is made over http:// and only afterwards "
                    "redirects to https. That first hop is unprotected: an on-path "
                    "attacker can see the request and can strip the redirect before "
                    "the browser ever reaches HTTPS."
                ),
                scope=f"Redirect chain of {resp.url}",
                remediation=(
                    "Redirect at the server/vhost level to https and enable HSTS so "
                    "the browser never makes the plaintext request in the first place."
                ),
                tags=["redirects", "transport", "hsts"],
            )
        )

    # ---- chain length ------------------------------------------------------
    if len(resp.redirect_chain) >= 3:
        findings.append(
            Finding(
                id="security.redirects.long_chain",
                title=f"Redirect chain is {len(resp.redirect_chain)} hops long",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(chain_text, source=source),
                reasoning=(
                    "Long chains slow first paint, break some crawlers and make it "
                    "easy for a stale hop to keep serving an insecure redirect. Each "
                    "hop is also another place where headers can leak."
                ),
                scope=f"Redirect chain of {resp.url}",
                remediation="Collapse the chain to a single hop at the edge.",
                tags=["redirects", "performance", "seo"],
            )
        )

    # ---- cross-host final hop ---------------------------------------------
    start_host = urlparse(resp.url).hostname
    end_host = urlparse(resp.final_url).hostname
    if start_host and end_host and start_host != end_host:
        findings.append(
            Finding(
                id="security.redirects.cross_host",
                title=f"Homepage redirects to a different host ({end_host})",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(chain_text, source=source),
                reasoning=(
                    f"Requests for {start_host} land on {end_host}. This is common "
                    "and correct when intentional, but it is also the exact pattern "
                    "used by subdomain-takeover and dangling-CNAME abuse — confirm "
                    "that the destination is expected."
                ),
                scope=f"Redirect chain of {resp.url}",
                tags=["redirects", "dns"],
            )
        )

    return findings


@register_probe(
    id="security.redirects.open_vector",
    category=Category.SECURITY,
    mode=ProbeMode.ACTIVE,
    phase=ProbePhase.ACTIVE,
    requires=("http_response",),
    title="Open-redirect vector detection",
    description="Looks for redirect parameters that accept external destinations.",
    tags=("redirects", "owasp-a01", "phishing"),
)
async def check_open_redirect_vector(ctx: ProbeContext) -> list[Finding]:
    """Send one benign external-destination test per redirect parameter.

    This is a *vector* check. ClientLens does not claim a vulnerability exists;
    it reports that a parameter accepts an external destination and requires
    manual verification.
    """
    resp = ctx.require("http_response")
    findings: list[Finding] = []
    if not resp.ok:
        return findings

    http = ctx.http_client
    base = resp.final_url or resp.url
    urlparse(base)

    candidates = _candidate_params(base)
    if not candidates:
        findings.append(
            Finding(
                id="security.redirects.open_vector_no_params",
                title="No redirect-style parameters found on the homepage URL",
                category=Category.SECURITY,
                kind=FindingKind.GAP,
                severity=Severity.INFO,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text(
                    f"Inspected query string of {base}",
                    source=base,
                ),
                reasoning=(
                    "No common redirect parameter names were present in the "
                    "homepage URL. Redirect parameters on other endpoints were not "
                    "tested in this pass."
                ),
                scope=f"Query parameters of {base}",
                tags=["redirects", "needs-review"],
            )
        )
        return findings

    probe_target = "https://example.com/clientlens-open-redirect-test"
    for param in candidates:
        test_url = _with_param(base, param, probe_target)
        test_resp = await http.get(test_url, follow=False)

        location = test_resp.headers.get("location", "")
        external = probe_target in location or urlparse(location).hostname in {
            "example.com",
            "www.example.com",
        }

        if external:
            findings.append(
                Finding(
                    id=f"security.redirects.open_vector.{param}",
                    title=f"Redirect parameter `{param}` accepts an external destination",
                    category=Category.SECURITY,
                    kind=FindingKind.VULNERABILITY_VECTOR,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LIKELY,
                    evidence=Evidence.http_response(
                        test_resp.status,
                        test_resp.headers,
                        source=test_url,
                    ),
                    reasoning=(
                        f"Requesting {test_url} produced a {test_resp.status} with "
                        f"Location: {location}. The parameter reflects the supplied "
                        "external host. If this response is reachable without further "
                        "checks, it can be used to build credible phishing links on "
                        "your own domain.\n\n"
                        "This is an attack-surface observation. Confirm manually "
                        "whether a server-side allowlist is applied before treating "
                        "it as a vulnerability."
                    ),
                    scope=f"GET {test_url}",
                    remediation=(
                        "Allowlist redirect destinations, or restrict redirects to "
                        "relative paths only. Never reflect a caller-supplied host."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"
                    ],
                    tags=["redirects", "open-redirect", "needs-review", "phishing"],
                )
            )
        else:
            findings.append(
                Finding(
                    id=f"security.redirects.open_vector.{param}.not_reflected",
                    title=f"Redirect parameter `{param}` did not reflect an external host",
                    category=Category.SECURITY,
                    kind=FindingKind.STRENGTH,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_response(
                        test_resp.status,
                        test_resp.headers,
                        source=test_url,
                    ),
                    reasoning=(
                        f"The test destination was not reflected in the response "
                        f"(status {test_resp.status}). This single probe found no "
                        "open-redirect behaviour on this parameter."
                    ),
                    scope=f"GET {test_url}",
                    tags=["redirects", "strength"],
                )
            )

    return findings


def _candidate_params(url: str) -> list[str]:
    query = parse_qs(urlparse(url).query)
    found = [p for p in OPEN_REDIRECT_PARAMS if p in query]
    # Also catch any parameter whose value looks like a URL.
    for key, values in query.items():
        for v in values:
            if v.startswith(("http://", "https://", "//")) and key not in found:
                found.append(key)
    return found


def _with_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[key] = [value]
    flat = [(k, v) for k, vals in query.items() for v in vals]
    return parsed._replace(query=urlencode(flat)).geturl()
