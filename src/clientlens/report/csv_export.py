"""CSV export — findings as a spreadsheet.

Useful for importing into a tracker (Linear, Jira, Sheets) or for pivoting in
Excel. One row per finding, one column per field, evidence summarised.
"""

from __future__ import annotations

import csv
from pathlib import Path

from ..core.models import ScanResult

COLUMNS = [
    "id",
    "severity",
    "confidence",
    "category",
    "kind",
    "title",
    "reasoning",
    "scope",
    "remediation",
    "evidence_source",
    "evidence_type",
    "tags",
    "probe_id",
    "fingerprint",
]


def to_csv_rows(result: ScanResult) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for f in result.findings:
        rows.append(
            {
                "id": _clean(f.id),
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "category": f.category.value,
                "kind": f.kind.value,
                "title": _clean(f.title),
                "reasoning": _clean(f.reasoning),
                "scope": _clean(f.scope),
                "remediation": _clean(f.remediation),
                "evidence_source": _clean(f.evidence.source),
                "evidence_type": f.evidence.type.value,
                "tags": ";".join(f.tags),
                "probe_id": f.probe_id,
                "fingerprint": f.fingerprint,
            }
        )
    return rows


def write_csv(result: ScanResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    rows = to_csv_rows(result)
    with p.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return p


def _clean(value: str) -> str:
    # Flatten newlines so each finding stays on one spreadsheet row.
    return " ".join(value.split()) if value else ""
