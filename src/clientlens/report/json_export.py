"""JSON export.

The JSON schema is the stable machine-readable contract. Anything downstream
(diffing, dashboards, ticket creation) should consume this rather than the
console or HTML renderers.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.models import ScanResult


def to_dict(result: ScanResult) -> dict:
    """Full scan result as a plain dict, safe to serialise."""
    payload = result.to_dict()
    payload["schema"] = {
        "name": "clientlens.scan",
        "version": "1.0",
        "confidence_levels": ["confirmed", "likely", "needs_review"],
        "note": (
            "Findings with confidence 'confirmed' carry directly observed evidence. "
            "'likely' findings are high-accuracy heuristics. 'needs_review' findings "
            "require human verification and must not be reported as confirmed issues."
        ),
    }
    return payload


def write_json(result: ScanResult, path: str | Path, *, indent: int = 2) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(to_dict(result), indent=indent, ensure_ascii=False), encoding="utf-8")
    return p


def load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
