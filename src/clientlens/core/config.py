"""Scan configuration and safety rails.

Safety is configuration, not convention. The engine refuses to run without an
explicit authorisation acknowledgement, and every request path is rate limited.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..branding import PROJECT, URL

DEFAULT_USER_AGENT = f"{PROJECT}/0.2 (authorized-audit; by Abdullah Al Noman; +{URL})"


@dataclass
class ScanConfig:
    """Everything that governs how a scan behaves toward the target."""

    # ---- authorisation & safety ----
    authorized: bool = False
    allow_private: bool = False
    respect_robots: bool = True
    user_agent: str = DEFAULT_USER_AGENT

    # ---- network budget ----
    timeout_s: float = 12.0
    connect_timeout_s: float = 6.0
    max_concurrent_requests: int = 6
    rate_limit_per_second: float = 5.0
    max_requests_per_scan: int = 120
    max_redirects: int = 5

    # ---- content limits ----
    max_body_bytes: int = 2_000_000
    evidence_snippet_chars: int = 1200
    link_sample_size: int = 200

    # ---- probe selection ----
    allow_active: bool = False
    include_probes: list[str] = field(default_factory=list)
    exclude_probes: list[str] = field(default_factory=list)
    preset: str = "standard"  # quick | standard | deep

    # ---- external services (all optional, all free) ----
    use_page_speed_insights: bool = False
    use_crtsh: bool = True

    # ---- reporting ----
    scan_mode: str = "passive"

    def __post_init__(self) -> None:
        if self.allow_active:
            self.scan_mode = "active"

    @property
    def headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
        }
