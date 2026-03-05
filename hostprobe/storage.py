"""SQLite storage backend for hostprobe scan results.

Supports multiple clients (tenants) so different teams, projects, or
engagements can store results in the same database without collision.

Schema
------
    clients  — one row per logical client/project
    scans    — one row per domain scan, linked to a client

Usage
-----
    db = HostprobeDB("results.db")
    db.save_report("acme-corp", report)
    history = db.get_reports(client="acme-corp")
    db.close()

Or as a context manager::

    with HostprobeDB("results.db") as db:
        db.save_report("acme-corp", report)
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from hostprobe.models import DomainReport, Verdict
from hostprobe.output import _dc_to_dict, _ReportEncoder


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id       INTEGER NOT NULL REFERENCES clients(id),
    domain          TEXT    NOT NULL,
    verdict         TEXT    NOT NULL,
    report_json     TEXT    NOT NULL,
    scan_started    TEXT,
    scan_finished   TEXT,
    scan_duration_s REAL,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scans_client_domain
    ON scans(client_id, domain);

CREATE INDEX IF NOT EXISTS idx_scans_domain
    ON scans(domain);

CREATE INDEX IF NOT EXISTS idx_scans_verdict
    ON scans(verdict);
"""


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------

class HostprobeDB:
    """SQLite storage for hostprobe results with multi-client support.

    Uses WAL journal mode for safe concurrent reads and single-writer
    concurrency.  The database file is created automatically if it
    does not exist.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._conn: sqlite3.Connection = sqlite3.connect(
            self.db_path,
            timeout=30,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- context manager ----------------------------------------------------

    def __enter__(self) -> HostprobeDB:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()

    # -- client management --------------------------------------------------

    def ensure_client(self, name: str) -> int:
        """Return the client id, creating the row if necessary."""
        cur = self._conn.execute(
            "SELECT id FROM clients WHERE name = ?", (name,)
        )
        row = cur.fetchone()
        if row:
            return row["id"]
        cur = self._conn.execute(
            "INSERT INTO clients (name) VALUES (?)", (name,)
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def list_clients(self) -> list[dict[str, Any]]:
        """Return all clients with their scan counts."""
        rows = self._conn.execute(
            """
            SELECT c.id, c.name, c.created_at,
                   COUNT(s.id) AS scan_count,
                   MAX(s.created_at) AS last_scan
            FROM clients c
            LEFT JOIN scans s ON s.client_id = c.id
            GROUP BY c.id
            ORDER BY c.name
            """
        ).fetchall()
        return [dict(r) for r in rows]

    # -- save / retrieve ----------------------------------------------------

    def save_report(self, client_name: str, report: DomainReport) -> int:
        """Persist a DomainReport under the given client.

        Returns the scan row id.
        """
        client_id = self.ensure_client(client_name)
        report_dict = _dc_to_dict(report)
        report_json = json.dumps(report_dict, cls=_ReportEncoder, default=str)

        scan_started = (
            report.scan_started.isoformat() if report.scan_started else None
        )
        scan_finished = (
            report.scan_finished.isoformat() if report.scan_finished else None
        )

        cur = self._conn.execute(
            """
            INSERT INTO scans
                (client_id, domain, verdict, report_json,
                 scan_started, scan_finished, scan_duration_s)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id,
                report.domain,
                report.verdict.value,
                report_json,
                scan_started,
                scan_finished,
                report.scan_duration_s,
            ),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def save_reports(
        self, client_name: str, reports: list[DomainReport]
    ) -> list[int]:
        """Save multiple reports in a single transaction."""
        ids: list[int] = []
        client_id = self.ensure_client(client_name)
        for report in reports:
            report_dict = _dc_to_dict(report)
            report_json = json.dumps(
                report_dict, cls=_ReportEncoder, default=str
            )
            scan_started = (
                report.scan_started.isoformat()
                if report.scan_started
                else None
            )
            scan_finished = (
                report.scan_finished.isoformat()
                if report.scan_finished
                else None
            )
            cur = self._conn.execute(
                """
                INSERT INTO scans
                    (client_id, domain, verdict, report_json,
                     scan_started, scan_finished, scan_duration_s)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_id,
                    report.domain,
                    report.verdict.value,
                    report_json,
                    scan_started,
                    scan_finished,
                    report.scan_duration_s,
                ),
            )
            ids.append(cur.lastrowid)  # type: ignore[arg-type]
        self._conn.commit()
        return ids

    def get_reports(
        self,
        client: str | None = None,
        domain: str | None = None,
        verdict: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query scan results with optional filters.

        Returns lightweight dicts (without full report_json parsed)
        for listing purposes.
        """
        clauses: list[str] = []
        params: list[Any] = []

        if client:
            clauses.append("c.name = ?")
            params.append(client)
        if domain:
            clauses.append("s.domain = ?")
            params.append(domain)
        if verdict:
            clauses.append("s.verdict = ?")
            params.append(verdict)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        rows = self._conn.execute(
            f"""
            SELECT s.id, c.name AS client, s.domain, s.verdict,
                   s.scan_started, s.scan_finished, s.scan_duration_s,
                   s.created_at
            FROM scans s
            JOIN clients c ON c.id = s.client_id
            {where}
            ORDER BY s.created_at DESC
            LIMIT ? OFFSET ?
            """,
            (*params, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_full_report(self, scan_id: int) -> dict[str, Any] | None:
        """Retrieve the full JSON report for a specific scan."""
        row = self._conn.execute(
            """
            SELECT s.id, c.name AS client, s.domain, s.verdict,
                   s.report_json, s.scan_started, s.scan_finished,
                   s.scan_duration_s, s.created_at
            FROM scans s
            JOIN clients c ON c.id = s.client_id
            WHERE s.id = ?
            """,
            (scan_id,),
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["report"] = json.loads(result.pop("report_json"))
        return result

    def get_domain_history(
        self, domain: str, client: str | None = None
    ) -> list[dict[str, Any]]:
        """Get all scans for a domain, optionally filtered by client.

        Useful for tracking changes over time.
        """
        clauses = ["s.domain = ?"]
        params: list[Any] = [domain]
        if client:
            clauses.append("c.name = ?")
            params.append(client)
        where = " AND ".join(clauses)

        rows = self._conn.execute(
            f"""
            SELECT s.id, c.name AS client, s.domain, s.verdict,
                   s.scan_started, s.scan_finished, s.scan_duration_s,
                   s.created_at
            FROM scans s
            JOIN clients c ON c.id = s.client_id
            WHERE {where}
            ORDER BY s.created_at DESC
            """,
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    def get_client_summary(self, client_name: str) -> dict[str, Any]:
        """Get a summary of scans for a client grouped by verdict."""
        client_id_row = self._conn.execute(
            "SELECT id FROM clients WHERE name = ?", (client_name,)
        ).fetchone()
        if not client_id_row:
            return {"client": client_name, "total": 0, "verdicts": {}}

        client_id = client_id_row["id"]
        rows = self._conn.execute(
            """
            SELECT verdict, COUNT(*) AS cnt
            FROM scans
            WHERE client_id = ?
            GROUP BY verdict
            """,
            (client_id,),
        ).fetchall()

        verdicts = {r["verdict"]: r["cnt"] for r in rows}
        total = sum(verdicts.values())
        return {
            "client": client_name,
            "total": total,
            "verdicts": verdicts,
        }

    def count_scans(
        self, client: str | None = None, domain: str | None = None
    ) -> int:
        """Count scans matching the given filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if client:
            clauses.append("c.name = ?")
            params.append(client)
        if domain:
            clauses.append("s.domain = ?")
            params.append(domain)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        row = self._conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM scans s
            JOIN clients c ON c.id = s.client_id
            {where}
            """,
            params,
        ).fetchone()
        return row["cnt"] if row else 0

    def delete_client(self, client_name: str) -> int:
        """Delete a client and all associated scans. Returns rows deleted."""
        client_row = self._conn.execute(
            "SELECT id FROM clients WHERE name = ?", (client_name,)
        ).fetchone()
        if not client_row:
            return 0
        client_id = client_row["id"]
        deleted = self._conn.execute(
            "DELETE FROM scans WHERE client_id = ?", (client_id,)
        ).rowcount
        self._conn.execute(
            "DELETE FROM clients WHERE id = ?", (client_id,)
        )
        self._conn.commit()
        return deleted
