"""SQLite storage for scan history.

Local, zero-config, and deliberately simple. The database stores the full JSON
payload per scan plus a small index row for listing and diffing. Nothing leaves
the machine.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from ..core.models import ScanResult


def default_db_path() -> Path:
    """Where the database lives: XDG-style data dir, overridable by env var."""
    override = os.environ.get("CLIENTLENS_DB")
    if override:
        return Path(override)
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "clientlens" / "scans.db"


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(String(32), primary_key=True)
    domain = Column(String(255), index=True)
    apex = Column(String(255), index=True)
    scheme = Column(String(16))
    scan_mode = Column(String(16))
    started_at = Column(DateTime, index=True)
    finished_at = Column(DateTime)
    duration_ms = Column(Integer)
    risk_score = Column(Integer, index=True)
    findings_total = Column(Integer)
    findings_critical = Column(Integer)
    findings_high = Column(Integer)
    findings_medium = Column(Integer)
    findings_low = Column(Integer)
    findings_info = Column(Integer)
    confirmed = Column(Integer)
    likely = Column(Integer)
    needs_review = Column(Integer)
    payload = Column(Text)  # full JSON
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))


class Storage:
    """Thin wrapper around the SQLAlchemy engine."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.path = Path(db_path) if db_path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            f"sqlite:///{self.path}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(self.engine)
        self._factory = sessionmaker(bind=self.engine, expire_on_commit=False)

    def session(self) -> Session:
        return self._factory()

    # ---- write -------------------------------------------------------------
    def save(self, result: ScanResult) -> ScanRecord:
        payload = result.to_json()
        counts = result.counts_by_severity
        conf = result.counts_by_confidence

        record = ScanRecord(
            id=result.scan_id,
            domain=result.target.domain,
            apex=result.target.apex,
            scheme=result.target.scheme,
            scan_mode=result.scan_mode,
            started_at=_parse(result.started_at),
            finished_at=_parse(result.finished_at),
            duration_ms=result.duration_ms,
            risk_score=result.risk_score,
            findings_total=len(result.findings),
            findings_critical=counts.get("critical", 0),
            findings_high=counts.get("high", 0),
            findings_medium=counts.get("medium", 0),
            findings_low=counts.get("low", 0),
            findings_info=counts.get("info", 0),
            confirmed=conf.get("confirmed", 0),
            likely=conf.get("likely", 0),
            needs_review=conf.get("needs_review", 0),
            payload=payload,
        )

        with self.session() as s:
            existing = s.get(ScanRecord, record.id)
            if existing:
                s.delete(existing)
                s.commit()
            s.add(record)
            s.commit()
            s.refresh(record)
        return record

    # ---- read --------------------------------------------------------------
    def list_scans(
        self,
        *,
        domain: str | None = None,
        limit: int = 50,
    ) -> list[ScanRecord]:
        with self.session() as s:
            stmt = select(ScanRecord).order_by(ScanRecord.started_at.desc()).limit(limit)
            if domain:
                stmt = stmt.where(ScanRecord.domain == domain)
            return list(s.scalars(stmt))

    def get(self, scan_id: str) -> ScanRecord | None:
        with self.session() as s:
            return s.get(ScanRecord, scan_id)

    def domains(self) -> list[str]:
        with self.session() as s:
            rows = s.scalars(select(ScanRecord.domain).distinct().order_by(ScanRecord.domain))
            return list(rows)

    def delete(self, scan_id: str) -> bool:
        with self.session() as s:
            record = s.get(ScanRecord, scan_id)
            if not record:
                return False
            s.delete(record)
            s.commit()
            return True

    # ---- diff --------------------------------------------------------------
    def diff(self, before_id: str, after_id: str) -> dict:
        """Compare two scans of the same domain by finding fingerprint."""
        before = self.get(before_id)
        after = self.get(after_id)
        if not before or not after:
            raise ValueError("both scan ids must exist")

        before_payload = json.loads(before.payload)
        after_payload = json.loads(after.payload)

        def index(payload: dict) -> dict[str, dict]:
            return {f["fingerprint"]: f for f in payload.get("findings", [])}

        b = index(before_payload)
        a = index(after_payload)

        added = [a[k] for k in a if k not in b]
        removed = [b[k] for k in b if k not in a]
        changed = []
        for key in set(a) & set(b):
            if a[key].get("severity") != b[key].get("severity"):
                changed.append(
                    {
                        "id": a[key]["id"],
                        "title": a[key]["title"],
                        "before": b[key]["severity"],
                        "after": a[key]["severity"],
                    }
                )

        return {
            "before": {"scan_id": before.id, "started_at": str(before.started_at), "risk": before.risk_score},
            "after": {"scan_id": after.id, "started_at": str(after.started_at), "risk": after.risk_score},
            "risk_delta": (after.risk_score or 0) - (before.risk_score or 0),
            "added": added,
            "removed": removed,
            "changed": changed,
        }


@dataclass
class ScanSummary:
    """Lightweight view used by the dashboard listing."""

    id: str
    domain: str
    started_at: str
    risk_score: int
    findings_total: int
    critical: int
    high: int


def _parse(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
