"""Core data models for ClientLens.

Every finding is evidence-backed and confidence-tagged. This module is the
contract that all probes and all report renderers agree on.

Design rules (accuracy guarantees)
----------------------------------
1. ``Confidence.CONFIRMED`` is reserved for directly observed values — a DNS
   answer, a response header, a DOM node, a TLS certificate field. Nothing
   inferred is ever marked ``CONFIRMED``.
2. Every ``Finding`` must carry ``evidence``. A finding without evidence is a
   bug, not a warning.
3. Absence of a signal is never reported as presence of its opposite.
   ``NotDetected`` is a distinct outcome from ``Absent``.
4. Vulnerability-shaped findings are capped at ``Confidence.LIKELY`` and use
   ``FindingKind.VULNERABILITY_VECTOR`` — ClientLens reports vectors, never
   confirmed exploits.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    """Business-impact severity, not CVSS.

    Severity is assigned from the *consequence to the business*, with written
    reasoning attached to each finding. A missing header on a marketing landing
    page is not the same as a missing header on an auth endpoint.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Confidence(str, Enum):
    """How certain we are that the finding reflects reality.

    CONFIRMED      - directly observed (DNS answer, header value, DOM node).
    LIKELY         - high-accuracy heuristic (fingerprint match, protocol trace).
    NEEDS_REVIEW   - human verification required before acting.
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    NEEDS_REVIEW = "needs_review"

    @property
    def label(self) -> str:
        return {
            "confirmed": "Confirmed",
            "likely": "Likely",
            "needs_review": "Needs manual review",
        }[self.value]


class FindingKind(str, Enum):
    """What sort of claim a finding makes.

    Keeping this separate from Severity is deliberate: it makes it impossible
    to accidentally render a heuristic as a verified vulnerability.
    """

    OBSERVATION = "observation"          # neutral fact ("cert expires in 12 days")
    MISCONFIGURATION = "misconfiguration"  # missing/incorrect control
    EXPOSURE = "exposure"                # something reachable that shouldn't be
    VULNERABILITY_VECTOR = "vulnerability_vector"  # attack surface, not a proven vuln
    STRENGTH = "strength"                # something done well (positive signal)
    GAP = "gap"                          # coverage gap ("not tested", "not enabled")


class Category(str, Enum):
    SECURITY = "security"
    MARKETING = "marketing"
    SHARED = "shared"


class EvidenceType(str, Enum):
    HTTP_HEADERS = "http_headers"
    HTTP_BODY_SNIPPET = "http_body_snippet"
    HTTP_RESPONSE = "http_response"
    DNS_RECORD = "dns_record"
    TLS_CERTIFICATE = "tls_certificate"
    HTML_NODE = "html_node"
    JSON_DOCUMENT = "json_document"
    URL_LIST = "url_list"
    TEXT = "text"
    NOT_APPLICABLE = "not_applicable"


class Presence(str, Enum):
    """Tri-state presence, so 'not detected' is never conflated with 'absent'."""

    PRESENT = "present"
    ABSENT = "absent"          # actively verified to be missing
    NOT_DETECTED = "not_detected"  # our checks did not surface it
    NOT_TESTED = "not_tested"


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    """Raw proof attached to a finding.

    The rule is simple: if a human opens ``raw``, they should be able to reach
    the same conclusion without trusting ClientLens.
    """

    type: EvidenceType
    raw: str
    summary: str = ""
    source: str = ""  # e.g. "GET https://example.com/", "TXT _dmarc.example.com"
    captured_at: str = ""

    def __post_init__(self) -> None:
        if not self.captured_at:
            self.captured_at = _now_iso()

    # Convenience constructors -------------------------------------------------
    @classmethod
    def http_headers(cls, headers: dict[str, str], source: str = "") -> Evidence:
        raw = "\n".join(f"{k}: {v}" for k, v in headers.items())
        return cls(type=EvidenceType.HTTP_HEADERS, raw=raw, summary=f"{len(headers)} headers", source=source)

    @classmethod
    def http_response(
        cls,
        status: int,
        headers: dict[str, str],
        body_snippet: str = "",
        source: str = "",
    ) -> Evidence:
        raw = f"HTTP {status}\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
        if body_snippet:
            raw += f"\n\n--- body (truncated) ---\n{body_snippet}"
        return cls(type=EvidenceType.HTTP_RESPONSE, raw=raw, summary=f"status {status}", source=source)

    @classmethod
    def dns_record(cls, name: str, rtype: str, values: list[str]) -> Evidence:
        raw = "\n".join(f"{name} {rtype} {v}" for v in values) or f"(no {rtype} record)"
        return cls(type=EvidenceType.DNS_RECORD, raw=raw, summary=f"{rtype} x{len(values)}", source=f"{rtype} {name}")

    @classmethod
    def tls_certificate(cls, raw: str, summary: str = "") -> Evidence:
        return cls(type=EvidenceType.TLS_CERTIFICATE, raw=raw, summary=summary)

    @classmethod
    def html_node(cls, selector: str, raw: str, source: str = "") -> Evidence:
        return cls(type=EvidenceType.HTML_NODE, raw=raw, summary=selector, source=source)

    @classmethod
    def text(cls, raw: str, summary: str = "", source: str = "") -> Evidence:
        return cls(type=EvidenceType.TEXT, raw=raw, summary=summary, source=source)

    @classmethod
    def urls(cls, urls: list[str], summary: str = "", source: str = "") -> Evidence:
        return cls(type=EvidenceType.URL_LIST, raw="\n".join(urls), summary=summary or f"{len(urls)} urls", source=source)

    @classmethod
    def none(cls, reason: str = "no evidence captured") -> Evidence:
        return cls(type=EvidenceType.NOT_APPLICABLE, raw=reason, summary=reason)


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """A single, evidence-backed claim about the target.

    ``id`` is a stable dotted identifier (``security.headers.hsts_missing``) so
    findings can be diffed across scans and suppressed by policy later.
    """

    id: str
    title: str
    category: Category
    kind: FindingKind
    severity: Severity
    confidence: Confidence
    evidence: Evidence
    reasoning: str = ""
    scope: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    # Denormalised helper fields, filled by the engine.
    probe_id: str = ""
    target: str = ""
    recorded_at: str = ""

    def __post_init__(self) -> None:
        if not self.recorded_at:
            self.recorded_at = _now_iso()
        # Hard guard: vulnerability-shaped claims can never be CONFIRMED.
        if self.kind is FindingKind.VULNERABILITY_VECTOR and self.confidence is Confidence.CONFIRMED:
            self.confidence = Confidence.LIKELY

    @property
    def fingerprint(self) -> str:
        """Stable hash for dedup/diff, based on id + evidence source."""
        basis = f"{self.id}|{self.evidence.source}|{self.title}"
        return hashlib.sha1(basis.encode()).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["kind"] = self.kind.value
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["evidence"]["type"] = self.evidence.type.value
        d["fingerprint"] = self.fingerprint
        return d


# --------------------------------------------------------------------------- #
# Probe execution metadata
# --------------------------------------------------------------------------- #
@dataclass
class ProbeResult:
    """Outcome of running one probe."""

    probe_id: str
    category: Category
    started_at: str
    finished_at: str = ""
    duration_ms: int = 0
    status: str = "ok"  # ok | error | skipped
    error: str = ""
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "ok"


@dataclass
class ScanTarget:
    """Normalised scan target."""

    raw: str
    domain: str
    apex: str
    scheme: str = "https"
    base_url: str = ""
    resolved_ips: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, raw: str) -> ScanTarget:
        from .target import normalize_target  # local import to avoid cycle

        return normalize_target(raw)


@dataclass
class ScanResult:
    """Complete result of one scan run."""

    target: ScanTarget
    scan_id: str
    started_at: str
    finished_at: str = ""
    duration_ms: int = 0
    clientlens_version: str = ""
    scan_mode: str = "passive"  # passive | active
    authorized: bool = False
    probe_results: list[ProbeResult] = field(default_factory=list)
    # Populated by the engine.
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.scan_id:
            self.scan_id = _make_scan_id(self.target.domain, self.started_at)
        if not self.finished_at:
            self.finished_at = _now_iso()
        if not self.clientlens_version:
            from .. import __version__

            self.clientlens_version = __version__

    # ---- derived views -------------------------------------------------------
    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def counts_by_confidence(self) -> dict[str, int]:
        counts = {c.value: 0 for c in Confidence}
        for f in self.findings:
            counts[f.confidence.value] += 1
        return counts

    @property
    def counts_by_category(self) -> dict[str, int]:
        counts = {c.value: 0 for c in Category}
        for f in self.findings:
            counts[f.category.value] += 1
        return counts

    @property
    def risk_score(self) -> int:
        """0-100 business-risk score.

        Point values are chosen so the scale behaves the way a reader expects:
        one confirmed critical finding is already a serious posture (≈20),
        four confirmed highs land around 40, and a pile of low-severity
        hygiene items stays in the tens rather than saturating the scale.

        Confidence is multiplicative so a stack of unverified heuristics can
        never outrank a single confirmed critical.
        """
        points = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        conf_weight = {
            Confidence.CONFIRMED: 1.0,
            Confidence.LIKELY: 0.55,
            Confidence.NEEDS_REVIEW: 0.15,
        }
        raw = sum(points[f.severity] * conf_weight[f.confidence] for f in self.findings)
        return min(100, round(raw))

    @property
    def strongest_points(self) -> list[Finding]:
        return [f for f in self.findings if f.kind is FindingKind.STRENGTH]

    @property
    def needs_review(self) -> list[Finding]:
        return [f for f in self.findings if f.confidence is Confidence.NEEDS_REVIEW]

    @property
    def probes_run(self) -> int:
        return len(self.probe_results)

    @property
    def probes_failed(self) -> int:
        return sum(1 for p in self.probe_results if p.status == "error")

    def findings_for(self, category: Category) -> list[Finding]:
        return [f for f in self.findings if f.category is category]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": asdict(self.target),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "clientlens_version": self.clientlens_version,
            "scan_mode": self.scan_mode,
            "authorized": self.authorized,
            "risk_score": self.risk_score,
            "counts": {
                "severity": self.counts_by_severity,
                "confidence": self.counts_by_confidence,
                "category": self.counts_by_category,
                "findings": len(self.findings),
                "probes_run": self.probes_run,
                "probes_failed": self.probes_failed,
            },
            "findings": [f.to_dict() for f in self.findings],
            "probe_results": [
                {
                    "probe_id": p.probe_id,
                    "category": p.category.value,
                    "status": p.status,
                    "duration_ms": p.duration_ms,
                    "error": p.error,
                    "findings": len(p.findings),
                }
                for p in self.probe_results
            ],
            "notes": self.notes,
            "coverage_gaps": self.coverage_gaps,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _make_scan_id(domain: str, started_at: str) -> str:
    basis = f"{domain}|{started_at}"
    return hashlib.sha256(basis.encode()).hexdigest()[:16]
