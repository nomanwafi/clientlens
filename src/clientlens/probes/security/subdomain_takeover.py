"""Subdomain takeover signals — dangling CNAMEs.

A CNAME pointing at a third-party service (GitHub Pages, Heroku, S3,
CloudFront, Azure, Shopify ...) becomes a takeover vector the moment the
service's claim lapses: anyone can register the orphaned name and serve
content — or receive the cookies and requests — under the victim's domain.

This probe resolves a bounded list of common names and reports CNAMEs into
known takeover-prone services as *vectors*, never as confirmed takeovers.
Confirming one requires registering the service, which is out of scope.
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
from ..shared.dns_client import resolve_record

# Bounded wordlist — the names a client site actually uses.
SUBDOMAIN_WORDS = (
    "www",
    "mail",
    "cdn",
    "api",
    "app",
    "dev",
    "staging",
    "test",
    "blog",
    "shop",
    "docs",
    "status",
    "portal",
    "admin",
)

# Services where an unclaimed subdomain is registrable by a third party.
TAKEOVER_PRONE = {
    "github.io": "GitHub Pages",
    "githubusercontent.com": "GitHub raw content",
    "herokuapp.com": "Heroku",
    "herokussl.com": "Heroku SSL",
    "s3.amazonaws.com": "Amazon S3",
    "s3-website": "Amazon S3 static website",
    "cloudfront.net": "Amazon CloudFront",
    "azurewebsites.net": "Azure App Service",
    "azureedge.net": "Azure CDN",
    "trafficmanager.net": "Azure Traffic Manager",
    "cloudapp.net": "Azure Cloud Service",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify storefront",
    "pantheon.io": "Pantheon",
    "wpengine.com": "WP Engine",
    "wpenginepowered.com": "WP Engine",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "surge.sh": "Surge",
    "readme.io": "ReadMe",
    "zendesk.com": "Zendesk",
    "helpjuice.com": "Helpjuice",
    "helpscoutdocs.com": "Help Scout",
    "cargo.site": "Cargo",
    "tumblr.com": "Tumblr",
    "wordpress.com": "WordPress.com",
    "fly.dev": "Fly.io",
    "ghost.io": "Ghost(Pro)",
    "statuspage.io": "Atlassian Statuspage",
    "ngrok.io": "ngrok",
}


@register_probe(
    id="security.subdomain_takeover",
    category=Category.SECURITY,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.ANALYSE,
    title="Subdomain takeover signals",
    description="Bounded DNS CNAME sweep for dangling third-party service targets.",
    tags=("dns", "takeover", "attack-surface", "brand-protection"),
)
async def check_subdomain_takeover(ctx: ProbeContext) -> list[Finding]:
    """Resolve common names and flag CNAMEs into takeover-prone services."""
    findings: list[Finding] = []
    apex = ctx.target.apex
    vectors: list[str] = []

    for word in SUBDOMAIN_WORDS:
        host = f"{word}.{apex}"
        answer = await resolve_record(host, "CNAME")
        if not answer.present:
            continue

        for target in answer.values:
            t = target.lower().rstrip(".")
            for suffix, service in TAKEOVER_PRONE.items():
                if t.endswith(suffix) or suffix in t:
                    vectors.append(f"{host}  ->  {t}  ({service})")
                    break

    if vectors:
        findings.append(
            Finding(
                id="security.subdomain_takeover.dangling_candidates",
                title=f"{len(vectors)} subdomain(s) point at third-party services",
                category=Category.SECURITY,
                kind=FindingKind.VULNERABILITY_VECTOR,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text("\n".join(vectors), source=f"DNS CNAME sweep of {apex}"),
                reasoning=(
                    "Each of these names delegates its content to a third-party "
                    "service. If the service account lapses — an unpaid bill, a "
                    "deleted project, a migrated site — the name stays pointed at "
                    "a claimable resource. An attacker who registers it then "
                    "serves content on the brand's domain, and receives any "
                    "traffic, cookies or OAuth callbacks the name receives. This "
                    "is a vector requiring manual verification: confirming it "
                    "would mean attempting the registration."
                ),
                scope=f"CNAME records for common names under {apex}",
                remediation=(
                    "For each name: confirm the service is actively claimed and "
                    "billing-active. Remove CNAMEs that no longer serve a purpose, "
                    "and add the names to certificate-transparency monitoring so "
                    "an unexpected cert issue is noticed."
                ),
                tags=["dns", "takeover", "attack-surface"],
            )
        )

    return findings
