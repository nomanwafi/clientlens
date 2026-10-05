"""Fingerprint database loader.

Bundled, local, and free. Tracking and technology signatures ship as JSON in
``data/fingerprints/`` so they can be updated without touching code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any


def _find_data_dir() -> Path:
    """Locate the fingerprint database directory.

    Checked in order so the tool works from a source checkout, an editable
    install and a wheel install without extra packaging configuration.
    """
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "data" / "fingerprints",        # src/clientlens/data/...
        here.parents[3] / "data" / "fingerprints",        # project root /data/...
        here.parents[1] / "data" / "fingerprints",        # clientlens/data/...
    ]
    for candidate in candidates:
        if candidate.is_dir() and (candidate / "tracking.json").exists():
            return candidate
    return candidates[0]


_DATA_DIR: Path | None = None


def data_dir() -> Path:
    global _DATA_DIR
    if _DATA_DIR is None:
        _DATA_DIR = _find_data_dir()
    return _DATA_DIR


@dataclass
class TrackerRule:
    id: str
    name: str
    vendor: str
    category: str
    src_patterns: list[str] = field(default_factory=list)
    inline_patterns: list[str] = field(default_factory=list)
    cookie_patterns: list[str] = field(default_factory=list)
    consent_relevant: bool = True
    privacy_friendly: bool = False
    deprecated: bool = False


@dataclass
class ConsentPlatform:
    id: str
    name: str
    patterns: list[str] = field(default_factory=list)


@dataclass
class TechRule:
    id: str
    name: str
    category: str
    html: list[str] = field(default_factory=list)
    headers: dict[str, list[str]] = field(default_factory=dict)
    meta_generator: list[str] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)


@dataclass
class FingerprintDB:
    trackers: list[TrackerRule]
    consent_platforms: list[ConsentPlatform]
    tech_rules: list[TechRule]
    tech_categories: dict[str, str]


@lru_cache(maxsize=1)
def load() -> FingerprintDB:
    tracking = _read_json("tracking.json")
    tech = _read_json("tech.json")

    trackers = [
        TrackerRule(
            id=t["id"],
            name=t["name"],
            vendor=t.get("vendor", ""),
            category=t.get("category", "other"),
            src_patterns=t.get("src_patterns", []),
            inline_patterns=t.get("inline_patterns", []),
            cookie_patterns=t.get("cookie_patterns", []),
            consent_relevant=t.get("consent_relevant", True),
            privacy_friendly=t.get("privacy_friendly", False),
            deprecated=t.get("deprecated", False),
        )
        for t in tracking.get("trackers", [])
    ]

    consent = [
        ConsentPlatform(id=c["id"], name=c["name"], patterns=c.get("patterns", []))
        for c in tracking.get("consent_platforms", [])
    ]

    tech_rules = []
    for r in tech.get("rules", []):
        name = r.get("name") or r.get("Name")
        if not name:
            continue
        tech_rules.append(
            TechRule(
                id=r["id"],
                name=name,
                category=r.get("category", "other"),
                html=r.get("html", []),
                headers=r.get("headers", {}),
                meta_generator=r.get("meta_generator", []),
                cookies=r.get("cookies", []),
            )
        )

    return FingerprintDB(
        trackers=trackers,
        consent_platforms=consent,
        tech_rules=tech_rules,
        tech_categories=tech.get("categories", {}),
    )


def _read_json(name: str) -> dict[str, Any]:
    path = data_dir() / name
    if not path.exists():
        raise FileNotFoundError(f"fingerprint database not found: {path}")
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Matching helpers
# --------------------------------------------------------------------------- #
def match_trackers(
    *,
    script_srcs: list[str],
    inline_scripts: list[str],
    cookie_names: list[str],
    html_blob: str = "",
) -> list[TrackerRule]:
    """Return every tracker rule matched by the observed signals.

    ``html_blob`` is the raw document source. It is searched because trackers
    also arrive as ``<img>`` pixels, ``<link>`` preloads and inside bundled
    scripts whose src does not contain the vendor name.
    """
    db = load()
    src_blob = "\n".join(script_srcs).lower()
    inline_blob = "\n".join(inline_scripts).lower()
    cookie_blob = "\n".join(cookie_names).lower()
    raw_blob = html_blob.lower()

    hits: list[TrackerRule] = []
    for rule in db.trackers:
        matched = False
        for pat in rule.src_patterns:
            if pat.lower() in src_blob or pat.lower() in raw_blob:
                matched = True
                break
        if not matched:
            for pat in rule.inline_patterns:
                if pat.lower() in inline_blob or pat.lower() in raw_blob:
                    matched = True
                    break
        if not matched:
            for pat in rule.cookie_patterns:
                if pat.lower() in cookie_blob:
                    matched = True
                    break
        if matched:
            hits.append(rule)
    return hits


def match_consent_platform(*, html_blob: str, script_srcs: list[str], cookie_names: list[str]) -> list[ConsentPlatform]:
    db = load()
    blob = (html_blob + "\n" + "\n".join(script_srcs) + "\n" + "\n".join(cookie_names)).lower()
    hits: list[ConsentPlatform] = []
    for platform in db.consent_platforms:
        for pat in platform.patterns:
            if pat.lower() in blob:
                hits.append(platform)
                break
    return hits


def match_tech(
    *,
    html_blob: str,
    headers: dict[str, str],
    meta_generator: str = "",
    cookie_names: list[str] | None = None,
) -> list[TechRule]:
    db = load()
    html_lower = html_blob.lower()
    meta_lower = meta_generator.lower()
    "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
    cookie_blob = "\n".join(cookie_names or []).lower()

    hits: list[TechRule] = []
    for rule in db.tech_rules:
        matched = False

        for pat in rule.html:
            if pat.lower() in html_lower:
                matched = True
                break

        if not matched and rule.meta_generator:
            for pat in rule.meta_generator:
                if pat.lower() in meta_lower:
                    matched = True
                    break

        if not matched and rule.headers:
            for header_name, values in rule.headers.items():
                actual = headers.get(header_name.lower(), "")
                if not actual:
                    continue
                if values == ["*"] or any(v.lower() in actual.lower() for v in values):
                    matched = True
                    break

        if not matched and rule.cookies:
            for cookie in rule.cookies:
                if cookie.lower() in cookie_blob:
                    matched = True
                    break

        if matched:
            hits.append(rule)
    return hits


def category_label(key: str) -> str:
    return load().tech_categories.get(key, key)
