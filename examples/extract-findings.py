#!/usr/bin/env python3
"""Turn a ClientLens JSON scan into a prioritised action list.

Usage:
    python examples/extract-findings.py reports/acme.json
    python examples/extract-findings.py reports/acme.json --confirmed-only
    python examples/extract-findings.py reports/acme.json --markdown > ticket.md

The output is deliberately filterable so it can be pasted straight into a
ticket, an email, or a spreadsheet without manual cleanup.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_MARK = {"critical": "!!!", "high": "!! ", "medium": "!  ", "low": "   ", "info": "   "}
CONFIDENCE_MARK = {"confirmed": "*", "likely": "~", "needs_review": "?"}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def select(findings: list[dict], *, confirmed_only: bool, min_severity: str, kind: str | None):
    out = []
    threshold = SEVERITY_ORDER[min_severity]
    for f in findings:
        if SEVERITY_ORDER[f["severity"]] > threshold:
            continue
        if confirmed_only and f["confidence"] != "confirmed":
            continue
        if kind and f["kind"] != kind:
            continue
        out.append(f)
    out.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["id"]))
    return out


def render_plain(findings: list[dict]) -> str:
    lines = []
    for f in findings:
        mark = SEVERITY_MARK[f["severity"]]
        conf = CONFIDENCE_MARK[f["confidence"]]
        lines.append(f"{mark} {conf} {f['title']}")
        lines.append(f"      id     : {f['id']}")
        if f.get("reasoning"):
            first = f["reasoning"].splitlines()[0]
            lines.append(f"      why    : {first}")
        if f.get("remediation"):
            first = f["remediation"].splitlines()[0]
            lines.append(f"      fix    : {first}")
        if f.get("scope"):
            lines.append(f"      scope  : {f['scope']}")
        lines.append("")
    return "\n".join(lines)


def render_markdown(findings: list[dict], header: str) -> str:
    lines = [header, ""]
    lines.append("| Sev | Conf | Finding | Why | Fix |")
    lines.append("|---|---|---|---|---|")
    for f in findings:
        why = f.get("reasoning", "").splitlines()[0] if f.get("reasoning") else ""
        fix = f.get("remediation", "").splitlines()[0] if f.get("remediation") else ""
        why = why.replace("|", "\\|")[:120]
        fix = fix.replace("|", "\\|")[:120]
        lines.append(
            f"| `{f['severity']}` | `{f['confidence']}` | {f['title']} | {why} | {fix} |"
        )
    lines.append("")
    lines.append("### Evidence")
    lines.append("")
    for f in findings:
        lines.append(f"**{f['id']}** — {f['title']}")
        lines.append("")
        lines.append(f"- scope: {f.get('scope', '')}")
        lines.append(f"- probe: `{f.get('probe_id', '')}`")
        if f.get("evidence", {}).get("raw"):
            raw = f["evidence"]["raw"][:300].replace("\n", "\n  ")
            lines.append("- evidence:")
            lines.append("  ```")
            lines.append(f"  {raw}")
            lines.append("  ```")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("scan_json", type=Path, help="Path to a ClientLens JSON report")
    ap.add_argument(
        "--min-severity",
        default="low",
        choices=list(SEVERITY_ORDER),
        help="Skip anything below this severity (default: low)",
    )
    ap.add_argument(
        "--confirmed-only",
        action="store_true",
        help="Only include findings with confidence=confirmed",
    )
    ap.add_argument(
        "--kind",
        default=None,
        choices=["misconfiguration", "exposure", "vulnerability_vector", "strength", "observation", "gap"],
        help="Only include this finding kind",
    )
    ap.add_argument("--markdown", action="store_true", help="Emit a Markdown table")
    ap.add_argument("--no-strengths", action="store_true", help="Hide positive findings")
    args = ap.parse_args()

    if not args.scan_json.exists():
        print(f"no such file: {args.scan_json}", file=sys.stderr)
        return 2

    data = load(args.scan_json)
    findings = data.get("findings", [])

    if args.no_strengths:
        findings = [f for f in findings if f["kind"] != "strength"]

    picked = select(
        findings,
        confirmed_only=args.confirmed_only,
        min_severity=args.min_severity,
        kind=args.kind,
    )

    header = (
        f"# ClientLens action list — {data['target']['domain']}\n"
        f"\n"
        f"Scan `{data['scan_id']}` · risk score **{data['risk_score']}/100** · "
        f"{len(picked)} findings selected of {len(data.get('findings', []))} total\n"
    )

    if args.markdown:
        print(render_markdown(picked, header))
    else:
        print(header)
        print(render_plain(picked) if picked else "  (nothing matched the filters)")
        print()
        print("Legend:  * confirmed   ~ likely   ? needs manual review")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
