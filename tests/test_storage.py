"""Tests for SQLite storage backend."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from hostprobe.models import (
    ASNInfo,
    DNSClassification,
    DNSResult,
    DecommissionSignals,
    DomainReport,
    EdgeCaseFlags,
    Verdict,
    WAFResult,
    WhoisResult,
)
from hostprobe.storage import HostprobeDB


def _make_report(domain: str = "example.com", verdict: Verdict = Verdict.ALIVE) -> DomainReport:
    """Build a minimal DomainReport for testing."""
    return DomainReport(
        domain=domain,
        verdict=verdict,
        reasoning=["Test reasoning"],
        dns=DNSResult(
            classification=DNSClassification.RESOLVED,
            rcode="NOERROR",
            records={"A": ["93.184.216.34"]},
            resolvers_queried=["system"],
            authoritative=False,
            dnssec_status="unsigned",
            cname_chain=[],
        ),
        whois=WhoisResult(
            registered=True,
            registrar="Test Registrar",
            creation_date=None,
            expiry_date=None,
            nameservers=["ns1.example.com"],
            recently_expired=False,
        ),
        subdomains=[],
        passive=None,
        icmp=None,
        port_probes=[],
        tls=None,
        smtp=None,
        http=None,
        banners=[],
        edge_cases=EdgeCaseFlags(),
        decommission=DecommissionSignals(),
        waf=None,
        asn=None,
        scan_started=None,
        scan_finished=None,
        scan_duration_s=3.5,
    )


class TestHostprobeDB:
    """Tests for HostprobeDB."""

    @pytest.fixture
    def db(self, tmp_path: Path) -> HostprobeDB:
        """Create an in-memory-like temp file DB."""
        db_path = tmp_path / "test.db"
        db = HostprobeDB(db_path)
        yield db
        db.close()

    def test_ensure_client_creates_new(self, db: HostprobeDB):
        cid = db.ensure_client("acme-corp")
        assert cid >= 1

    def test_ensure_client_idempotent(self, db: HostprobeDB):
        cid1 = db.ensure_client("acme-corp")
        cid2 = db.ensure_client("acme-corp")
        assert cid1 == cid2

    def test_list_clients_empty(self, db: HostprobeDB):
        clients = db.list_clients()
        assert clients == []

    def test_list_clients_with_data(self, db: HostprobeDB):
        db.ensure_client("alpha")
        db.ensure_client("beta")
        clients = db.list_clients()
        names = [c["name"] for c in clients]
        assert "alpha" in names
        assert "beta" in names

    def test_save_report(self, db: HostprobeDB):
        report = _make_report()
        scan_id = db.save_report("acme-corp", report)
        assert scan_id >= 1

    def test_save_and_retrieve(self, db: HostprobeDB):
        report = _make_report("test.com")
        db.save_report("acme-corp", report)

        results = db.get_reports(client="acme-corp")
        assert len(results) == 1
        assert results[0]["domain"] == "test.com"
        assert results[0]["verdict"] == "alive"
        assert results[0]["client"] == "acme-corp"

    def test_get_full_report(self, db: HostprobeDB):
        report = _make_report("full.com")
        scan_id = db.save_report("client-a", report)

        full = db.get_full_report(scan_id)
        assert full is not None
        assert full["domain"] == "full.com"
        assert "report" in full
        assert full["report"]["domain"] == "full.com"
        assert full["report"]["verdict"] == "alive"

    def test_get_full_report_not_found(self, db: HostprobeDB):
        assert db.get_full_report(9999) is None

    def test_multi_client_isolation(self, db: HostprobeDB):
        r1 = _make_report("site-a.com")
        r2 = _make_report("site-b.com")

        db.save_report("client-x", r1)
        db.save_report("client-y", r2)

        x_results = db.get_reports(client="client-x")
        y_results = db.get_reports(client="client-y")

        assert len(x_results) == 1
        assert x_results[0]["domain"] == "site-a.com"
        assert len(y_results) == 1
        assert y_results[0]["domain"] == "site-b.com"

    def test_save_reports_batch(self, db: HostprobeDB):
        reports = [_make_report(f"d{i}.com") for i in range(5)]
        ids = db.save_reports("batch-client", reports)
        assert len(ids) == 5

        results = db.get_reports(client="batch-client")
        assert len(results) == 5

    def test_filter_by_domain(self, db: HostprobeDB):
        db.save_report("c", _make_report("foo.com"))
        db.save_report("c", _make_report("bar.com"))

        results = db.get_reports(domain="foo.com")
        assert len(results) == 1
        assert results[0]["domain"] == "foo.com"

    def test_filter_by_verdict(self, db: HostprobeDB):
        db.save_report("c", _make_report("alive.com", Verdict.ALIVE))
        db.save_report("c", _make_report("dead.com", Verdict.LIKELY_DEAD))

        alive = db.get_reports(verdict="alive")
        assert len(alive) == 1
        assert alive[0]["domain"] == "alive.com"

    def test_domain_history(self, db: HostprobeDB):
        db.save_report("c", _make_report("tracked.com"))
        db.save_report("c", _make_report("tracked.com"))

        history = db.get_domain_history("tracked.com")
        assert len(history) == 2

    def test_client_summary(self, db: HostprobeDB):
        db.save_report("proj", _make_report("a.com", Verdict.ALIVE))
        db.save_report("proj", _make_report("b.com", Verdict.ALIVE))
        db.save_report("proj", _make_report("c.com", Verdict.LIKELY_DEAD))

        summary = db.get_client_summary("proj")
        assert summary["total"] == 3
        assert summary["verdicts"]["alive"] == 2
        assert summary["verdicts"]["likely_dead"] == 1

    def test_client_summary_not_found(self, db: HostprobeDB):
        summary = db.get_client_summary("nonexistent")
        assert summary["total"] == 0

    def test_count_scans(self, db: HostprobeDB):
        db.save_report("c", _make_report("a.com"))
        db.save_report("c", _make_report("b.com"))
        assert db.count_scans() == 2
        assert db.count_scans(client="c") == 2
        assert db.count_scans(domain="a.com") == 1

    def test_delete_client(self, db: HostprobeDB):
        db.save_report("rm-me", _make_report("x.com"))
        db.save_report("rm-me", _make_report("y.com"))
        db.save_report("keep", _make_report("z.com"))

        deleted = db.delete_client("rm-me")
        assert deleted == 2

        assert db.count_scans(client="rm-me") == 0
        assert db.count_scans(client="keep") == 1

    def test_delete_nonexistent_client(self, db: HostprobeDB):
        assert db.delete_client("ghost") == 0

    def test_context_manager(self, tmp_path: Path):
        db_path = tmp_path / "ctx.db"
        with HostprobeDB(db_path) as db:
            db.save_report("ctx-client", _make_report())
        # DB is closed after with block — file should exist
        assert db_path.exists()

    def test_waf_and_asn_persist(self, db: HostprobeDB):
        report = _make_report("waf.com")
        report.waf = WAFResult(
            detected=True, provider="Cloudflare",
            evidence=["cf-ray header"], is_blocking=True,
        )
        report.asn = ASNInfo(
            ip="1.2.3.4", asn=13335, asn_org="Cloudflare",
            isp="Cloudflare Inc", country="US", city="SF",
            is_cloud=True, cloud_provider="Cloudflare",
        )
        scan_id = db.save_report("waf-client", report)

        full = db.get_full_report(scan_id)
        assert full is not None
        assert full["report"]["waf"]["detected"] is True
        assert full["report"]["waf"]["provider"] == "Cloudflare"
        assert full["report"]["asn"]["asn"] == 13335

    def test_pagination(self, db: HostprobeDB):
        for i in range(20):
            db.save_report("pager", _make_report(f"d{i}.com"))

        page1 = db.get_reports(client="pager", limit=5, offset=0)
        page2 = db.get_reports(client="pager", limit=5, offset=5)
        assert len(page1) == 5
        assert len(page2) == 5
        # Pages should be different
        p1_domains = {r["domain"] for r in page1}
        p2_domains = {r["domain"] for r in page2}
        assert p1_domains.isdisjoint(p2_domains)

    def test_list_clients_shows_scan_count(self, db: HostprobeDB):
        db.save_report("counted", _make_report("a.com"))
        db.save_report("counted", _make_report("b.com"))

        clients = db.list_clients()
        counted = next(c for c in clients if c["name"] == "counted")
        assert counted["scan_count"] == 2
        assert counted["last_scan"] is not None
