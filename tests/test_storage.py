"""Storage and diff tests."""

from __future__ import annotations

import json

import pytest

from clientlens.core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    ScanResult,
    Severity,
)
from clientlens.core.target import normalize_target
from clientlens.storage.db import Storage


def make_result(scan_id: str = "", *, findings: list[Finding] | None = None, domain: str = "example.com"):
    return ScanResult(
        target=normalize_target(domain),
        scan_id=scan_id,
        started_at="2026-01-01T00:00:00+00:00",
        findings=findings or [],
    )


def finding(fid: str, *, severity=Severity.LOW, confidence=Confidence.CONFIRMED, title="t"):
    return Finding(
        id=fid,
        title=title,
        category=Category.SECURITY,
        kind=FindingKind.MISCONFIGURATION,
        severity=severity,
        confidence=confidence,
        evidence=Evidence.text("x", source=fid),
    )


@pytest.fixture
def storage(tmp_path):
    return Storage(tmp_path / "test.db")


class TestStorage:
    def test_save_and_get(self, storage):
        result = make_result("scan-1", findings=[finding("a.b")])
        record = storage.save(result)
        assert record.id == "scan-1"

        loaded = storage.get("scan-1")
        assert loaded is not None
        payload = json.loads(loaded.payload)
        assert payload["target"]["domain"] == "example.com"
        assert len(payload["findings"]) == 1

    def test_list_scans(self, storage):
        storage.save(make_result("s1"))
        storage.save(make_result("s2", domain="other.com"))
        assert len(storage.list_scans()) == 2
        assert len(storage.list_scans(domain="other.com")) == 1

    def test_domains(self, storage):
        storage.save(make_result("s1", domain="a.com"))
        storage.save(make_result("s2", domain="b.com"))
        assert storage.domains() == ["a.com", "b.com"]

    def test_delete(self, storage):
        storage.save(make_result("s1"))
        assert storage.delete("s1") is True
        assert storage.get("s1") is None
        assert storage.delete("nope") is False

    def test_resave_same_id_replaces(self, storage):
        storage.save(make_result("s1", findings=[finding("a")]))
        storage.save(make_result("s1", findings=[finding("a"), finding("b")]))
        payload = json.loads(storage.get("s1").payload)
        assert len(payload["findings"]) == 2


class TestDiff:
    def test_diff_added_and_removed(self, storage):
        before = make_result(
            "before",
            findings=[finding("sec.a", title="Kept"), finding("sec.b", title="Gone")],
        )
        after = make_result(
            "after",
            findings=[finding("sec.a", title="Kept"), finding("sec.c", title="New")],
        )
        storage.save(before)
        storage.save(after)

        diff = storage.diff("before", "after")
        assert diff["risk_delta"] == 0
        assert [f["title"] for f in diff["added"]] == ["New"]
        assert [f["title"] for f in diff["removed"]] == ["Gone"]
        assert diff["changed"] == []

    def test_diff_severity_change(self, storage):
        storage.save(make_result("before", findings=[finding("sec.a", severity=Severity.LOW)]))
        storage.save(make_result("after", findings=[finding("sec.a", severity=Severity.HIGH)]))

        diff = storage.diff("before", "after")
        assert len(diff["changed"]) == 1
        assert diff["changed"][0]["before"] == "low"
        assert diff["changed"][0]["after"] == "high"
        assert diff["risk_delta"] == 9  # high=10 minus low=1

    def test_diff_missing_scan_raises(self, storage):
        storage.save(make_result("before"))
        with pytest.raises(ValueError):
            storage.diff("before", "nope")


class TestWebApi:
    def test_api_scans_and_findings(self, tmp_path):
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from clientlens.storage.db import Storage
        from clientlens.web.app import create_app

        storage = Storage(tmp_path / "web.db")
        storage.save(make_result("s1", findings=[finding("a.b", severity=Severity.HIGH)]))

        app = create_app(storage)
        client = TestClient(app)

        r = client.get("/api/scans")
        assert r.status_code == 200
        assert r.json()[0]["id"] == "s1"

        r = client.get("/api/scans/s1")
        assert r.status_code == 200
        assert r.json()["scan_id"] == "s1"

        r = client.get("/api/scans/s1/findings")
        assert r.status_code == 200
        assert len(r.json()) == 1

        r = client.get("/api/scans/s1/findings?severity=high")
        assert len(r.json()) == 1
        r = client.get("/api/scans/s1/findings?severity=low")
        assert len(r.json()) == 0

        r = client.get("/")
        assert r.status_code == 200
        assert "example.com" in r.text

        r = client.get("/scans/s1")
        assert r.status_code == 200

        r = client.get("/api/scans/nope")
        assert r.status_code == 404

    def test_diff_endpoint(self, tmp_path):
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from clientlens.storage.db import Storage
        from clientlens.web.app import create_app

        storage = Storage(tmp_path / "web2.db")
        storage.save(make_result("b", findings=[finding("x", title="Old")]))
        storage.save(make_result("a", findings=[finding("y", title="New")]))

        client = TestClient(create_app(storage))
        r = client.get("/api/diff/b/a")
        assert r.status_code == 200
        body = r.json()
        assert body["added"][0]["title"] == "New"

        r = client.get("/diff/b/a")
        assert r.status_code == 200
        assert "New" in r.text
