"""Cookie attribute checks.

We report the attributes that are actually on the wire. A cookie with no
``Secure`` flag is a fact; whether it matters depends on what the cookie does,
which is why reasoning states the consequence rather than asserting a breach.
"""

from __future__ import annotations

from ...core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from ...core.registry import ProbeContext, ProbeMode, ProbePhase, register_probe

SESSION_HINTS = ("session", "sess", "sid", "auth", "token", "jwt", "phpsessid", "jsessionid")
TRACKER_HINTS = ("_ga", "_gid", "_fbp", "_gcl", "utm_", "ajs_", "mp_")


@register_probe(
    id="security.cookies",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    requires=("http_response",),
    title="Cookie security attributes",
    description="Secure / HttpOnly / SameSite flags on Set-Cookie values.",
    tags=("cookies", "session"),
)
async def check_cookies(ctx: ProbeContext) -> list[Finding]:
    """Inspect Set-Cookie attributes on the homepage response."""
    resp = ctx.require("http_response")
    findings: list[Finding] = []

    if not resp.ok:
        return findings

    source = f"GET {resp.final_url}"
    # httpx flattens multiple Set-Cookie into one entry in some transports; we
    # parse both the combined and individual cases defensively.
    raw_cookies = _collect_set_cookie(resp.headers)
    if not raw_cookies:
        findings.append(
            Finding(
                id="security.cookies.none_set",
                title="No cookies set on the homepage response",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.http_headers(resp.headers, source=source),
                reasoning=(
                    "No Set-Cookie header was observed on this response. That is "
                    "neither good nor bad on its own — cookies may be set on later "
                    "requests or by client-side JavaScript."
                ),
                scope=f"Set-Cookie headers of {resp.final_url}",
                tags=["cookies"],
            )
        )
        return findings

    for raw in raw_cookies:
        findings.extend(_evaluate_cookie(raw, source, resp.final_url))

    return findings


def _collect_set_cookie(headers: dict[str, str]) -> list[str]:
    out: list[str] = []
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        # Split on commas that separate cookies, but not commas inside Expires.
        parts = _split_cookie_header(value)
        out.extend(parts)
    return out


def _split_cookie_header(value: str) -> list[str]:
    cookies: list[str] = []
    current = ""
    for chunk in value.split(","):
        if current and "=" not in chunk.split(";")[0]:
            current += "," + chunk
        else:
            if current:
                cookies.append(current.strip())
            current = chunk
    if current:
        cookies.append(current.strip())
    return [c for c in cookies if c]


def _evaluate_cookie(raw: str, source: str, url: str) -> list[Finding]:
    findings: list[Finding] = []
    segments = [s.strip() for s in raw.split(";")]
    if not segments or "=" not in segments[0]:
        return findings

    name = segments[0].split("=", 1)[0].strip()
    attrs = {}
    for seg in segments[1:]:
        if "=" in seg:
            k, v = seg.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[seg.strip().lower()] = ""

    flags = {s.lower() for s in segments[1:] if "=" not in s}
    lowered_name = name.lower()

    looks_session = any(h in lowered_name for h in SESSION_HINTS)
    looks_tracker = any(lowered_name.startswith(h) or h in lowered_name for h in TRACKER_HINTS)

    evidence = Evidence.text(raw, summary=f"Set-Cookie: {name}", source=source)

    if "secure" not in flags:
        findings.append(
            Finding(
                id=f"security.cookies.{_slug(name)}.insecure",
                title=f"Cookie `{name}` missing the `Secure` flag",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM if looks_session else Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    "Without `Secure` the cookie is eligible to be sent over plain "
                    "http:// as well as https://. On any network where an attacker "
                    "can downgrade or observe plaintext, this cookie crosses in the "
                    "clear."
                ),
                scope=f"Set-Cookie on {url}",
                remediation=f"Add `Secure` to the `{name}` cookie.",
                tags=["cookies", "secure-flag"] + (["session"] if looks_session else []),
            )
        )

    if "httponly" not in flags and looks_session:
        findings.append(
            Finding(
                id=f"security.cookies.{_slug(name)}.no_httponly",
                title=f"Session cookie `{name}` missing the `HttpOnly` flag",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    "Without `HttpOnly` any JavaScript on the page — including a "
                    "single injected script — can read this cookie and exfiltrate "
                    "the session."
                ),
                scope=f"Set-Cookie on {url}",
                remediation=f"Add `HttpOnly` to the `{name}` cookie.",
                tags=["cookies", "httponly", "session"],
            )
        )

    samesite = attrs.get("samesite", "")
    if not samesite:
        findings.append(
            Finding(
                id=f"security.cookies.{_slug(name)}.no_samesite",
                title=f"Cookie `{name}` has no `SameSite` attribute",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    "Without `SameSite` the cookie is eligible for cross-site "
                    "sending, which widens the window for CSRF-style abuse. Browsers "
                    "default to `Lax` in modern versions but that is an implicit "
                    "behaviour, not an explicit control."
                ),
                scope=f"Set-Cookie on {url}",
                remediation=f"Set `SameSite=Lax` (or `Strict`) on `{name}`.",
                tags=["cookies", "samesite"],
            )
        )
    elif samesite.lower() == "none" and "secure" not in flags:
        findings.append(
            Finding(
                id=f"security.cookies.{_slug(name)}.samesite_none_insecure",
                title=f"Cookie `{name}` uses `SameSite=None` without `Secure`",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    "`SameSite=None` requires `Secure`. Without it modern browsers "
                    "reject the cookie outright, so the intended behaviour silently "
                    "fails as well as being unsafe."
                ),
                scope=f"Set-Cookie on {url}",
                remediation=f"Add `Secure` to `{name}`, or stop using SameSite=None.",
                tags=["cookies", "samesite"],
            )
        )

    if looks_tracker:
        findings.append(
            Finding(
                id=f"security.cookies.{_slug(name)}.tracker",
                title=f"Analytics/tracking cookie `{name}` observed",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                reasoning=(
                    "This cookie is set by an analytics or advertising stack. It is "
                    "listed here because it is part of the site's data-collection "
                    "surface and should be covered by the consent and privacy notice."
                ),
                scope=f"Set-Cookie on {url}",
                tags=["cookies", "tracking", "privacy"],
            )
        )

    return findings


def _slug(name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in name).strip("_").lower() or "cookie"
