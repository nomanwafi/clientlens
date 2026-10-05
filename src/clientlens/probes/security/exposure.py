"""Exposure checks: sensitive paths, security.txt, robots.txt, source control leftovers.

A path that returns 200 with the expected content is reported as *observed*.
A path that does not return anything is reported as "not detected in this
wordlist", never as "does not exist".
"""

from __future__ import annotations

import re

from ...core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from ...core.registry import ProbeContext, ProbeMode, ProbePhase, register_probe

# Deliberately small and specific. This is reconnaissance, not brute force.
SENSITIVE_PATHS: list[tuple[str, str, Severity, str]] = [
    (
        "/.git/HEAD",
        "Git repository metadata exposed",
        Severity.CRITICAL,
        "An exposed .git directory lets an attacker reconstruct the full source "
        "history, including secrets that were ever committed and later removed.",
    ),
    (
        "/.git/config",
        "Git config exposed",
        Severity.CRITICAL,
        "The git config can reveal remote URLs including embedded credentials.",
    ),
    (
        "/.env",
        "Environment file exposed",
        Severity.CRITICAL,
        ".env files routinely contain database passwords, API keys and cloud "
        "credentials in plaintext.",
    ),
    (
        "/.svn/entries",
        "Subversion metadata exposed",
        Severity.HIGH,
        "Source control metadata lets an attacker reconstruct the working copy.",
    ),
    (
        "/.DS_Store",
        "macOS .DS_Store exposed",
        Severity.LOW,
        "Directory listings leak filenames and folder structure, which speeds up "
        "targeted enumeration.",
    ),
    (
        "/backup.zip",
        "Backup archive reachable",
        Severity.CRITICAL,
        "A downloadable backup is a complete data exfiltration opportunity and "
        "commonly includes database dumps.",
    ),
    (
        "/dump.sql",
        "SQL dump reachable",
        Severity.CRITICAL,
        "A database dump is a direct data breach.",
    ),
    (
        "/wp-config.php.bak",
        "WordPress config backup reachable",
        Severity.CRITICAL,
        "wp-config.php contains database credentials; a .bak copy serves them as plain text.",
    ),
    (
        "/phpinfo.php",
        "phpinfo() page exposed",
        Severity.MEDIUM,
        "phpinfo() discloses absolute paths, module versions and environment "
        "variables — a complete fingerprint for an attacker.",
    ),
    (
        "/server-status",
        "Apache server-status exposed",
        Severity.MEDIUM,
        "server-status leaks request URIs, client IPs and backend worker state.",
    ),
    (
        "/actuator/health",
        "Spring Boot actuator endpoint exposed",
        Severity.MEDIUM,
        "Actuator endpoints expose application internals and can lead to RCE on "
        "some configurations.",
    ),
    (
        "/elmah.axd",
        "ASP.NET error log exposed",
        Severity.HIGH,
        "ELMAH exposes full exception details including stack traces and "
        "sometimes connection strings.",
    ),
]

# Paths that are useful to know about but are not inherently a problem.
DISCLOSURE_PATHS: list[tuple[str, str, str]] = [
    ("/robots.txt", "robots.txt", "Reveals which paths the site asks crawlers to avoid."),
    ("/sitemap.xml", "sitemap.xml", "Reveals the published URL inventory."),
    ("/security.txt", "security.txt", "Security contact disclosure."),
    ("/.well-known/security.txt", "security.txt (RFC 9116)", "Security contact disclosure."),
    ("/humans.txt", "humans.txt", "Team/credits disclosure."),
]


@register_probe(
    id="security.exposure.paths",
    category=Category.SECURITY,
    mode=ProbeMode.ACTIVE,
    phase=ProbePhase.ACTIVE,
    requires=("http_response",),
    title="Sensitive path exposure",
    description="Small, targeted wordlist for high-signal exposed files and admin endpoints.",
    tags=("exposure", "recon", "owasp-a05"),
)
async def check_sensitive_paths(ctx: ProbeContext) -> list[Finding]:
    """Probe a small set of high-signal paths and report only what answers."""
    findings: list[Finding] = []
    base = ctx.target.base_url
    http = ctx.http_client

    confirmed = 0
    for path, title, severity, reasoning in SENSITIVE_PATHS:
        url = f"{base}{path}"
        resp = await http.get(url, follow=False)

        if resp.status in (200, 206) and _looks_real(resp, path):
            confirmed += 1
            findings.append(
                Finding(
                    id=f"security.exposure.{_slug(path)}",
                    title=title,
                    category=Category.SECURITY,
                    kind=FindingKind.EXPOSURE,
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_response(
                        resp.status, resp.headers, resp.snippet(400), source=url
                    ),
                    reasoning=reasoning,
                    scope=f"GET {url} returned {resp.status}",
                    remediation=f"Block or remove `{path}` at the web server, and rotate any "
                    "credentials that were ever stored in it.",
                    tags=["exposure", "sensitive-path"],
                )
            )
        elif resp.status in (200, 206):
            findings.append(
                Finding(
                    id=f"security.exposure.{_slug(path)}.uncertain",
                    title=f"{path} returned {resp.status} but content is inconclusive",
                    category=Category.SECURITY,
                    kind=FindingKind.VULNERABILITY_VECTOR,
                    severity=Severity.LOW,
                    confidence=Confidence.NEEDS_REVIEW,
                    evidence=Evidence.http_response(
                        resp.status, resp.headers, resp.snippet(200), source=url
                    ),
                    reasoning=(
                        "The path answered with a success status but the body does "
                        "not match the expected shape for this file. It may be a "
                        "catch-all route returning the SPA shell. Verify manually."
                    ),
                    scope=f"GET {url} returned {resp.status}",
                    remediation=f"If `{path}` is not intentional, return 404 for it.",
                    tags=["exposure", "needs-review"],
                )
            )

    if confirmed == 0:
        findings.append(
            Finding(
                id="security.exposure.paths_clean",
                title="No sensitive paths detected in the tested wordlist",
                category=Category.SECURITY,
                kind=FindingKind.GAP,
                severity=Severity.INFO,
                confidence=Confidence.NEEDS_REVIEW,
                evidence=Evidence.text(
                    f"Probed {len(SENSITIVE_PATHS)} paths under {base}. "
                    "None returned recognisable sensitive content.",
                    source=base,
                ),
                reasoning=(
                    "This is a negative result against a small, high-signal "
                    "wordlist — NOT proof that nothing is exposed. A larger "
                    "enumeration would be needed before drawing that conclusion."
                ),
                scope=f"{len(SENSITIVE_PATHS)} paths under {base}",
                tags=["exposure", "negative-result", "needs-review"],
            )
        )

    return findings


@register_probe(
    id="security.exposure.disclosure",
    category=Category.SECURITY,
    mode=ProbeMode.ACTIVE,
    phase=ProbePhase.ACTIVE,
    requires=("http_response",),
    title="robots.txt / security.txt / sitemap disclosure",
    description="Files that describe the site's own security posture and crawl surface.",
    tags=("exposure", "disclosure"),
)
async def check_disclosure_files(ctx: ProbeContext) -> list[Finding]:
    """Fetch the well-known disclosure files and report what they contain."""
    findings: list[Finding] = []
    base = ctx.target.base_url
    http = ctx.http_client

    for path, label, why in DISCLOSURE_PATHS:
        url = f"{base}{path}"
        resp = await http.get(url, follow=False)

        if resp.status != 200 or not resp.body.strip():
            continue

        if label.startswith("security.txt"):
            findings.extend(_parse_security_txt(resp, url, label))
        elif label == "robots.txt":
            findings.extend(_parse_robots(resp, url))
        else:
            findings.append(
                Finding(
                    id=f"security.exposure.{_slug(path)}",
                    title=f"{label} present",
                    category=Category.SECURITY,
                    kind=FindingKind.OBSERVATION,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    evidence=Evidence.http_response(
                        resp.status, resp.headers, resp.snippet(300), source=url
                    ),
                    reasoning=why,
                    scope=f"GET {url}",
                    tags=["disclosure"],
                )
            )

    return findings


def _parse_security_txt(resp, url: str, label: str) -> list[Finding]:
    findings: list[Finding] = []
    body = resp.body
    fields = {}
    for line in body.splitlines():
        if ":" in line and not line.strip().startswith("#"):
            k, v = line.split(":", 1)
            fields[k.strip().lower()] = v.strip()

    findings.append(
        Finding(
            id="security.exposure.security_txt_present",
            title=f"{label} published",
            category=Category.SECURITY,
            kind=FindingKind.STRENGTH,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.http_response(
                resp.status, resp.headers, resp.snippet(500), source=url
            ),
            reasoning=(
                "A security.txt gives researchers a sanctioned way to report "
                "issues instead of going public or going dark. It is a positive "
                "signal of a mature security programme."
            ),
            scope=f"GET {url}",
            tags=["disclosure", "security-txt", "strength"],
        )
    )

    if "expires" in fields:
        findings.append(
            Finding(
                id="security.exposure.security_txt_expiry",
                title=f"security.txt declares Expires: {fields['expires']}",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(body[:400], source=url),
                reasoning=(
                    "RFC 9116 requires an Expires field. Once that date passes the "
                    "file is stale and should be regenerated — an expired security.txt "
                    "silently stops working as a contact channel."
                ),
                scope=f"GET {url}",
                tags=["disclosure", "security-txt"],
            )
        )
    else:
        findings.append(
            Finding(
                id="security.exposure.security_txt_no_expiry",
                title="security.txt has no Expires field",
                category=Category.SECURITY,
                kind=FindingKind.MISCONFIGURATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(body[:400], source=url),
                reasoning="RFC 9116 requires Expires; without it the file is non-conformant and has no review cycle.",
                scope=f"GET {url}",
                remediation="Add an `Expires:` field and regenerate the file periodically.",
                tags=["disclosure", "security-txt"],
            )
        )

    return findings


def _parse_robots(resp, url: str) -> list[Finding]:
    findings: list[Finding] = []
    body = resp.body
    disallows = [
        line.split(":", 1)[1].strip()
        for line in body.splitlines()
        if line.strip().lower().startswith("disallow:")
    ]
    disallows = [d for d in disallows if d]

    findings.append(
        Finding(
            id="security.exposure.robots_txt",
            title="robots.txt present",
            category=Category.SECURITY,
            kind=FindingKind.OBSERVATION,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            evidence=Evidence.http_response(
                resp.status, resp.headers, resp.snippet(600), source=url
            ),
            reasoning=(
                f"{len(disallows)} Disallow path(s) declared. robots.txt is a "
                "request, not an access control — but the paths it names are a "
                "useful hint at where the interesting content lives."
            ),
            scope=f"GET {url}",
            tags=["disclosure", "robots"],
        )
    )

    if disallows:
        findings.append(
            Finding(
                id="security.exposure.robots_disallow_paths",
                title=f"robots.txt names {len(disallows)} restricted path(s)",
                category=Category.SECURITY,
                kind=FindingKind.OBSERVATION,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.urls(disallows[:30], source=url),
                reasoning=(
                    "These paths are the ones the site explicitly asks crawlers to "
                    "avoid. Enforcement is the web server's job, not robots.txt's."
                ),
                scope=f"Disallow directives in {url}",
                tags=["disclosure", "robots"],
            )
        )

    return findings


# --------------------------------------------------------------------------- #
def _looks_real(resp, path: str) -> bool:
    body = resp.body or ""
    lowered = body[:800].lower()
    if path == "/.git/HEAD":
        return bool(re.search(r"ref:\s+refs/", body[:200]))
    if path.endswith((".git/config",)):
        return "[core]" in lowered or "repositoryformatversion" in lowered
    if path == "/.env":
        return bool(re.search(r"^\s*[A-Z0-9_]+\s*=", body[:800], re.M))
    if path.endswith(".sql"):
        return "create table" in lowered or "insert into" in lowered
    if path.endswith((".zip", ".bak")):
        ctype = resp.headers.get("content-type", "")
        return "html" not in ctype.lower() and len(body) > 200
    if path == "/phpinfo.php":
        return "phpinfo()" in lowered or "php version" in lowered
    if path == "/.DS_Store":
        return body.lstrip()[:8] == "\x00\x00\x00\x01Bud1" or "Bud1" in body[:20]
    if path == "/elmah.axd":
        return "error log" in lowered or "elmah" in lowered
    if "actuator" in path:
        return body.strip().startswith("{") and "status" in lowered
    if path == "/server-status":
        return "apache server status" in lowered or "server uptime" in lowered
    return len(body) > 40 and "not found" not in lowered[:200]


def _slug(path: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in path).strip("_").lower() or "path"
