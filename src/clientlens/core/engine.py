"""Scan engine — orchestrates capture, analysis and reporting.

The engine enforces three things:

1. **Authorisation** — no run without an explicit acknowledgement.
2. **Budget** — every network request goes through the rate-limited client.
3. **Dependency ordering** — a probe that declares ``requires=("http_response",)``
   never runs unless that fact was actually captured.

Everything else is just wiring.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime

from .config import ScanConfig
from .exceptions import AuthorizationRequired
from .models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    ScanResult,
    ScanTarget,
    Severity,
)
from .registry import (
    REGISTRY,
    ProbeContext,
    ProbeMode,
    ProbePhase,
    register_probe,
    run_probe,
)
from .target import normalize_target

log = logging.getLogger("clientlens.engine")

CAPTURE_PROBE_ID = "shared.capture"


class ScanEngine:
    """Runs a full scan against a single target."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()

    async def run(self, raw_target: str) -> ScanResult:
        if not self.config.authorized:
            raise AuthorizationRequired(
                "Scanning without an authorisation acknowledgement is refused. "
                "Pass --i-am-authorized (CLI) or set ScanConfig(authorized=True). "
                "Only scan systems you own or have written permission to test."
            )

        target = normalize_target(raw_target, allow_private=self.config.allow_private)
        started = time.perf_counter()
        started_at = _now_iso()

        result = ScanResult(
            target=target,
            scan_id="",
            started_at=started_at,
            scan_mode=self.config.scan_mode,
            authorized=self.config.authorized,
        )

        log.info("scan start target=%s mode=%s", target.domain, self.config.scan_mode)

        async with _import_http_client()(self.config) as http:
            ctx = ProbeContext(target=target, config=self.config, http_client=http)

            specs = self._select_specs()
            grouped = REGISTRY.by_phase(specs)

            # ---- run phases with progress -----------------------------------
            all_specs = []
            all_specs.extend(grouped[ProbePhase.CAPTURE])
            all_specs.extend(grouped[ProbePhase.ANALYSE])
            if self.config.allow_active:
                all_specs.extend(grouped[ProbePhase.ACTIVE])

            from rich.progress import (
                BarColumn,
                MofNCompleteColumn,
                Progress,
                SpinnerColumn,
                TextColumn,
                TimeRemainingColumn,
            )

            progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=None),
                MofNCompleteColumn(),
                TimeRemainingColumn(),
                transient=True,
                console=None,
            )

            task_id = progress.add_task("Auditing", total=len(all_specs))
            with progress:
                # ---- phase 1: capture -------------------------------------------
                await self._run_phase(
                    grouped[ProbePhase.CAPTURE], ctx, result, progress=progress, task_id=task_id
                )

                # ---- phase 2: analyse -------------------------------------------
                await self._run_phase(
                    grouped[ProbePhase.ANALYSE], ctx, result, progress=progress, task_id=task_id
                )

                # ---- phase 3: active --------------------------------------------
                if self.config.allow_active:
                    await self._run_phase(
                        grouped[ProbePhase.ACTIVE], ctx, result, progress=progress, task_id=task_id
                    )
                else:
                    skipped = grouped[ProbePhase.ACTIVE]
                    if skipped:
                        result.coverage_gaps.append(
                            f"{len(skipped)} active probes skipped (passive mode). "
                            "Re-run with --active for deeper coverage."
                        )

            result.notes.append(f"HTTP request budget used: {http.requests_used}")

        # Aggregate findings and record coverage gaps.
        for pr in result.probe_results:
            result.findings.extend(pr.findings)
        result.findings.sort(key=lambda f: (-f.severity.weight, f.category.value, f.id))

        self._record_coverage_gaps(result, specs_run=[p.probe_id for p in result.probe_results])

        result.finished_at = _now_iso()
        result.duration_ms = int((time.perf_counter() - started) * 1000)

        log.info(
            "scan done target=%s findings=%d duration=%dms",
            target.domain,
            len(result.findings),
            result.duration_ms,
        )
        return result

    # ------------------------------------------------------------------ #
    def _select_specs(self):
        """Apply preset / include / exclude filters to the probe registry."""
        # Explicit --include overrides everything else.
        include = self.config.include_probes or None
        exclude = list(self.config.exclude_probes)

        if not include:
            if self.config.preset == "quick":
                exclude.extend(
                    [
                        "security.subdomains",
                        "security.cors",
                        "security.email_auth",
                        "security.exposure",
                        "security.transport",
                        "security.dns.dnssec",
                        "security.dns.www_redirect",
                        "security.headers.csp_deep",
                        "marketing.performance",
                        "marketing.tech_stack",
                        "marketing.third_party",
                        "marketing.pwa",
                        "marketing.accessibility",
                        "marketing.forms",
                        "marketing.schema",
                    ]
                )
            elif self.config.preset == "deep":
                # Deep runs everything allowed by mode; no extra exclusions.
                pass
            else:  # standard
                exclude.extend(
                    [
                        # Keep deep transport/DNS only in deep preset.
                        "security.transport",
                        "security.dns.dnssec",
                        "security.dns.www_redirect",
                        "security.headers.csp_deep",
                        "marketing.third_party",
                        "marketing.pwa",
                        "marketing.accessibility",
                        "marketing.forms",
                    ]
                )

        return REGISTRY.select(
            include=include,
            exclude=exclude or None,
            allow_active=self.config.allow_active,
        )

    async def _run_phase(
        self, specs, ctx: ProbeContext, result: ScanResult, *, progress=None, task_id=None
    ) -> None:
        if not specs:
            return
        semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)

        async def _guarded(spec):
            async with semaphore:
                pr = await run_probe(spec, ctx)
                if progress and task_id is not None:
                    progress.advance(task_id)
                return pr

        probe_results = await asyncio.gather(*(_guarded(s) for s in specs))
        for pr in probe_results:
            result.probe_results.append(pr)
            # Publish facts a probe produced so downstream probes can use them.
            for f in pr.findings:
                if f.evidence.source:
                    ctx.set_fact(f"finding:{f.id}", f)
            if pr.status == "error":
                log.warning("probe %s error: %s", pr.probe_id, pr.error)

    def _record_coverage_gaps(self, result: ScanResult, specs_run: list[str]) -> None:
        """Explicitly say what was *not* tested, so silence is never mistaken for health."""
        gaps: list[str] = []

        if not self.config.allow_active:
            gaps.append(
                "Active interaction tests (admin path enumeration, open-redirect "
                "param injection, CORS origin reflection) were NOT run."
            )
        if "marketing.performance.pagespeed" not in specs_run:
            gaps.append(
                "Field Core Web Vitals not collected (Google PageSpeed Insights / CrUX "
                "not enabled). Local lab metrics only."
            )
        gaps.append(
            "No authenticated testing was performed — anything behind login is out of scope."
        )
        gaps.append(
            "No vulnerability exploitation was attempted. Vulnerability-shaped findings "
            "are attack-surface vectors requiring manual verification."
        )
        gaps.append(
            "Subdomain enumeration is CT-log + wordlist based; private/internal "
            "subdomains are not discoverable from outside."
        )
        gaps.append(
            "Traffic, ranking and backlink metrics are not collected (third-party "
            "data sources are disabled in this build)."
        )
        result.coverage_gaps.extend(gaps)


# --------------------------------------------------------------------------- #
# Capture probe — the single place that touches the network for passive scans.
# --------------------------------------------------------------------------- #
def _import_http_client():
    from ..probes.shared.http_client import HttpCaptureClient

    return HttpCaptureClient


async def _capture_probe(ctx: ProbeContext) -> list[Finding]:
    """Fetch the homepage, TLS certificate and DNS records once.

    Provides facts: ``http_response``, ``html``, ``dns``, ``tls``. Subsequent
    probes consume these and never re-fetch.
    """
    from ..probes.shared import dns_client as dns
    from ..probes.shared.html import parse_html

    target: ScanTarget = ctx.target
    http = ctx.http_client

    findings: list[Finding] = []

    # ---- HTTP -------------------------------------------------------------
    url = f"{target.scheme}://{target.domain}/"
    resp = await http.get(url, follow=True)
    ctx.set_fact("http_response", resp)

    if not resp.ok:
        findings.append(
            Finding(
                id="shared.capture.http_unreachable",
                title=f"Could not fetch {url}",
                category=Category.SHARED,
                kind=FindingKind.GAP,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence=Evidence.text(resp.error or f"status {resp.status}", source=url),
                reasoning="The homepage did not return a usable response, so all "
                "HTTP-derived checks are unavailable for this target.",
                scope="HTTP reachability",
            )
        )
    elif resp.is_html:
        ctx.set_fact("html", parse_html(url, resp.final_url, resp.body))

    # ---- DNS --------------------------------------------------------------
    snapshot = await dns.resolve_all(target.domain)
    ctx.set_fact("dns", snapshot)

    ips = snapshot.values("A") + snapshot.values("AAAA")
    if ips:
        target.resolved_ips = ips

    # ---- TLS --------------------------------------------------------------
    host_for_tls = target.domain
    tls_info = await asyncio.to_thread(dns.lookup_certificate_names, host_for_tls, 443)
    ctx.set_fact("tls", tls_info)

    return findings


# Register the capture probe at import time.
register_probe(
    id=CAPTURE_PROBE_ID,
    category=Category.SHARED,
    mode=ProbeMode.PASSIVE,
    phase=ProbePhase.CAPTURE,
    provides=("http_response", "html", "dns", "tls"),
    title="Capture homepage, DNS and TLS material",
    timeout_s=60.0,
)(_capture_probe)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def confidence_note(conf: Confidence) -> str:
    return {
        Confidence.CONFIRMED: "Directly observed — raw evidence attached.",
        Confidence.LIKELY: "High-accuracy heuristic — verify before acting on it.",
        Confidence.NEEDS_REVIEW: "Human verification required before acting on it.",
    }[conf]
