"""Tests for hostprobe.db_cli — database query & export subcommand."""

from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest

from hostprobe.db_cli import (
    _flatten_report_row,
    _format_table,
    _print_clients_table,
    _print_domain_history,
    _print_dump,
    _print_full_report,
    _print_scans_table,
    _truncate,
    build_db_parser,
    db_main,
    export_csv as export_csv_func,
    export_csv_stdout,
)
from hostprobe.models import (
    DNSClassification,
    DNSResult,
    DecommissionSignals,
    DomainReport,
    EdgeCaseFlags,
    HTTPResult,
    ICMPResult,
    PortProbe,
    PortState,
    Verdict,
    WhoisResult,
)
from hostprobe.storage import HostprobeDB


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_report(
    domain: str = "test.com",
    verdict: Verdict = Verdict.ALIVE,
) -> DomainReport:
    """Create a minimal DomainReport for testing."""
    return DomainReport(
        domain=domain,
        verdict=verdict,
        reasoning=["reason A", "VERDICT: " + verdict.value],
        dns=DNSResult(
            classification=DNSClassification.RESOLVED,
            rcode="NOERROR",
            records={
                "A": ["1.2.3.4"],
                "AAAA": [],
                "MX": [],
                "NS": ["ns1.test.com"],
                "TXT": [],
                "CNAME": [],
                "SOA": [],
                "CAA": [],
                "SRV": [],
            },
            cname_chain=[],
            resolvers_queried=["8.8.8.8"],
            authoritative=True,
            dnssec_status="secure",
        ),
        whois=WhoisResult(
            registered=True,
            registrar="TestReg",
            creation_date=datetime(2020, 1, 1),
            expiry_date=datetime(2027, 1, 1),
            nameservers=["ns1.test.com"],
            recently_expired=False,
        ),
        subdomains=[],
        passive=None,
        icmp=ICMPResult(reachable=True, latency_ms=12.0),
        port_probes=[
            PortProbe(port=443, state=PortState.OPEN, latency_ms=5.0, method="connect"),
            PortProbe(port=80, state=PortState.CLOSED, latency_ms=3.0, method="connect"),
        ],
        tls=None,
        smtp=None,
        http=HTTPResult(status_code=200, server_header="nginx"),
        banners=[],
        edge_cases=EdgeCaseFlags(),
        decommission=DecommissionSignals(),
        scan_started=datetime(2026, 3, 5, 10, 0, 0),
        scan_finished=datetime(2026, 3, 5, 10, 0, 5),
        scan_duration_s=4.8,
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def populated_db(db_path: Path) -> Path:
    """Create a database with sample data and return its path."""
    with HostprobeDB(db_path) as db:
        db.save_report("ClientA", _make_report("alpha.com", Verdict.ALIVE))
        db.save_report("ClientA", _make_report("beta.com", Verdict.LIKELY_DEAD))
        db.save_report("ClientB", _make_report("gamma.org", Verdict.INVESTIGATE))
        db.save_report("ClientB", _make_report("delta.net", Verdict.FILTERED))
    return db_path


# ---------------------------------------------------------------------------
# Unit tests: helpers
# ---------------------------------------------------------------------------


class TestTruncate:
    def test_short_string_unchanged(self):
        assert _truncate("hello", 10) == "hello"

    def test_exact_length(self):
        assert _truncate("hello", 5) == "hello"

    def test_truncation(self):
        result = _truncate("hello world", 8)
        assert len(result) == 8
        assert result.endswith("…")
        assert result == "hello w…"


class TestFormatTable:
    def test_basic_table(self):
        table = _format_table(
            ["NAME", "VALUE"],
            [["foo", "123"], ["bar", "456"]],
            color=False,
        )
        assert "NAME" in table
        assert "VALUE" in table
        assert "foo" in table
        assert "123" in table
        assert "bar" in table
        assert "456" in table
        # Check box drawing chars
        assert "┌" in table
        assert "└" in table
        assert "│" in table
        assert "─" in table

    def test_empty_rows(self):
        table = _format_table(["A", "B"], [], color=False)
        assert "A" in table
        assert "B" in table
        # Should have top/header/separator/bottom but no data rows
        lines = table.strip().split("\n")
        assert len(lines) == 4  # top, header, separator, bottom

    def test_with_col_colors(self):
        table = _format_table(
            ["STATUS"],
            [["alive"]],
            color=True,
            col_colors={0: {"alive": "\033[32m"}},
        )
        # Should contain ANSI codes
        assert "\033[32m" in table


class TestFlattenReportRow:
    def test_minimal(self):
        row = _flatten_report_row({
            "id": 1,
            "client": "test",
            "domain": "x.com",
            "verdict": "alive",
            "scan_started": "2026-01-01",
            "scan_finished": "2026-01-01",
            "scan_duration_s": 3.2,
            "created_at": "2026-01-01",
            "report": {
                "dns": {
                    "classification": "resolved",
                    "rcode": "NOERROR",
                    "records": {"A": ["1.2.3.4"], "NS": ["ns1.x.com"]},
                    "dnssec_status": "secure",
                },
                "whois": {"registered": "True", "registrar": "Reg"},
                "icmp": {"reachable": "True", "latency_ms": "10"},
                "port_probes": [
                    {"port": 443, "state": "open"},
                    {"port": 80, "state": "closed"},
                ],
                "http": {"status_code": 200, "server_header": "nginx"},
                "reasoning": ["line1", "line2"],
            },
        })
        assert row["domain"] == "x.com"
        assert row["verdict"] == "alive"
        assert row["dns_classification"] == "resolved"
        assert row["dns_records_a"] == "1.2.3.4"
        assert row["open_ports"] == "443"
        assert row["closed_ports"] == "80"
        assert row["http_status"] == "200"
        assert "line1" in row["reasoning"]

    def test_missing_report(self):
        row = _flatten_report_row({
            "id": 1,
            "client": "test",
            "domain": "y.com",
            "verdict": "alive",
        })
        assert row["domain"] == "y.com"
        assert row["dns_classification"] == ""


# ---------------------------------------------------------------------------
# Integration tests: table printing
# ---------------------------------------------------------------------------


class TestPrintScansTable:
    def test_prints_table(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = _print_scans_table(db)
        out = capsys.readouterr().out
        assert count == 4
        assert "alpha.com" in out
        assert "beta.com" in out
        assert "gamma.org" in out
        assert "ALIVE" in out

    def test_filter_by_client(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = _print_scans_table(db, client="ClientA")
        out = capsys.readouterr().out
        assert count == 2
        assert "alpha.com" in out
        assert "gamma.org" not in out

    def test_filter_by_verdict(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = _print_scans_table(db, verdict="alive")
        out = capsys.readouterr().out
        assert count == 1
        assert "alpha.com" in out

    def test_no_results(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = _print_scans_table(db, client="NoSuch")
        assert count == 0


class TestPrintClientsTable:
    def test_prints_clients(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = _print_clients_table(db)
        out = capsys.readouterr().out
        assert count == 2
        assert "ClientA" in out
        assert "ClientB" in out

    def test_empty_db(self, db_path, capsys):
        with HostprobeDB(db_path) as db:
            count = _print_clients_table(db)
        assert count == 0


class TestPrintFullReport:
    def test_prints_report(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            ok = _print_full_report(db, 1)
        out = capsys.readouterr().out
        assert ok is True
        assert "alpha.com" in out

    def test_not_found(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            ok = _print_full_report(db, 999)
        assert ok is False


class TestPrintDomainHistory:
    def test_prints_history(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            # Save a second scan for the same domain
            db.save_report("ClientA", _make_report("alpha.com", Verdict.LIKELY_DEAD))
            count = _print_domain_history(db, "alpha.com")
        out = capsys.readouterr().out
        assert count == 2
        assert "alpha.com" in out

    def test_no_history(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = _print_domain_history(db, "nonexistent.com")
        assert count == 0


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------


class TestExportCSV:
    def test_export_to_file(self, populated_db, tmp_path):
        out_path = str(tmp_path / "export.csv")
        with HostprobeDB(populated_db) as db:
            count = export_csv_func(db, out_path)
        assert count == 4
        # Verify CSV contents
        with open(out_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 4
        domains = {r["domain"] for r in rows}
        assert "alpha.com" in domains
        assert "gamma.org" in domains

    def test_export_filtered(self, populated_db, tmp_path):
        out_path = str(tmp_path / "filtered.csv")
        with HostprobeDB(populated_db) as db:
            count = export_csv_func(db, out_path, client="ClientB")
        assert count == 2

    def test_export_empty(self, populated_db, tmp_path):
        out_path = str(tmp_path / "empty.csv")
        with HostprobeDB(populated_db) as db:
            count = export_csv_func(db, out_path, client="NoSuch")
        assert count == 0

    def test_export_csv_stdout(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = export_csv_stdout(db)
        out = capsys.readouterr().out
        assert count == 4
        assert "alpha.com" in out
        assert "id,client,domain" in out


# ---------------------------------------------------------------------------
# CLI entry point (db_main)
# ---------------------------------------------------------------------------


class TestDbMain:
    def test_db_not_found(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            db_main([str(tmp_path / "nonexistent.db")])
        assert exc.value.code == 1

    def test_list_scans(self, populated_db, capsys):
        with pytest.raises(SystemExit) as exc:
            db_main([str(populated_db)])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "alpha.com" in out

    def test_list_clients(self, populated_db, capsys):
        with pytest.raises(SystemExit) as exc:
            db_main([str(populated_db), "--clients"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "ClientA" in out

    def test_full_report(self, populated_db, capsys):
        with pytest.raises(SystemExit) as exc:
            db_main([str(populated_db), "--full", "1"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "alpha.com" in out

    def test_history(self, populated_db, capsys):
        with pytest.raises(SystemExit) as exc:
            db_main([str(populated_db), "--history", "alpha.com"])
        assert exc.value.code == 0

    def test_export_csv_file(self, populated_db, tmp_path):
        csv_path = str(tmp_path / "out.csv")
        with pytest.raises(SystemExit) as exc:
            db_main([str(populated_db), "--export-csv", csv_path])
        assert exc.value.code == 0
        assert Path(csv_path).exists()

    def test_export_csv_stdout(self, populated_db, capsys):
        with pytest.raises(SystemExit) as exc:
            db_main([str(populated_db), "--export-csv", "-"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "alpha.com" in out

    def test_filter_by_client(self, populated_db, capsys):
        with pytest.raises(SystemExit) as exc:
            db_main([str(populated_db), "--client", "ClientB"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "gamma.org" in out
        assert "alpha.com" not in out

    def test_filter_by_verdict(self, populated_db, capsys):
        with pytest.raises(SystemExit) as exc:
            db_main([str(populated_db), "--verdict", "alive"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "alpha.com" in out
        assert "beta.com" not in out


# ---------------------------------------------------------------------------
# Dump tests (--dump: full data pretty cards)
# ---------------------------------------------------------------------------


class TestPrintDump:
    def test_prints_all_fields(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = _print_dump(db)
        out = capsys.readouterr().out
        assert count == 4
        assert "alpha.com" in out
        assert "[GENERAL]" in out
        assert "[DNS]" in out
        assert "[WHOIS]" in out
        assert "[CONNECTIVITY]" in out
        assert "[HTTP]" in out

    def test_filter_by_client(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = _print_dump(db, client="ClientA")
        out = capsys.readouterr().out
        assert count == 2
        assert "alpha.com" in out
        assert "gamma.org" not in out

    def test_filter_by_verdict(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = _print_dump(db, verdict="alive")
        out = capsys.readouterr().out
        assert count == 1
        assert "alpha.com" in out

    def test_no_results(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = _print_dump(db, client="NoSuch")
        assert count == 0

    def test_contains_dns_records(self, populated_db, capsys):
        with HostprobeDB(populated_db) as db:
            count = _print_dump(db)
        out = capsys.readouterr().out
        # Should contain actual DNS data from the report
        assert "1.2.3.4" in out or "ns1.test.com" in out


class TestDbMainDump:
    def test_dump_flag(self, populated_db, capsys):
        with pytest.raises(SystemExit) as exc:
            db_main([str(populated_db), "--dump"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "[GENERAL]" in out
        assert "[DNS]" in out
        assert "alpha.com" in out

    def test_dump_with_csv(self, populated_db, tmp_path, capsys):
        csv_path = str(tmp_path / "dump.csv")
        with pytest.raises(SystemExit) as exc:
            db_main([str(populated_db), "--dump", "--export-csv", csv_path])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "[GENERAL]" in out
        assert Path(csv_path).exists()
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 4

    def test_dump_with_filter(self, populated_db, capsys):
        with pytest.raises(SystemExit) as exc:
            db_main([str(populated_db), "--dump", "--client", "ClientB"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "gamma.org" in out
        assert "alpha.com" not in out


# ---------------------------------------------------------------------------
# CLI routing from main()
# ---------------------------------------------------------------------------


class TestCLIRouting:
    def test_db_subcommand_routes(self, populated_db, capsys):
        """Verify `hostprobe db <path>` routes to db_main."""
        from hostprobe.cli import main

        with pytest.raises(SystemExit) as exc:
            main(["db", str(populated_db)])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "alpha.com" in out
