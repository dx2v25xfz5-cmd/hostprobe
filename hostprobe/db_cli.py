"""CLI subcommand for querying and exporting hostprobe database results.

Usage
-----
    hostprobe db results.db                        # pretty table of all scans
    hostprobe db results.db --client acme          # filter by client
    hostprobe db results.db --verdict alive         # filter by verdict
    hostprobe db results.db --export-csv out.csv   # export all to CSV
    hostprobe db results.db --clients              # list clients summary
    hostprobe db results.db --domain example.com   # filter by domain
    hostprobe db results.db --full 42              # full report for scan id
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from hostprobe.storage import HostprobeDB


# ---------------------------------------------------------------------------
# ANSI color helpers (standalone, no dependency on output.py)
# ---------------------------------------------------------------------------

class _C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"


def _use_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(color: str, text: str, enabled: bool = True) -> str:
    return f"{color}{text}{_C.RESET}" if enabled else text


# ---------------------------------------------------------------------------
# Verdict color mapping
# ---------------------------------------------------------------------------

_VERDICT_COLORS = {
    "alive": _C.GREEN,
    "likely_dead": _C.RED,
    "filtered": _C.YELLOW,
    "partial": _C.YELLOW,
    "investigate": _C.MAGENTA,
    "recently_decommissioned": _C.CYAN,
}


# ---------------------------------------------------------------------------
# Pretty table rendering
# ---------------------------------------------------------------------------

def _truncate(text: str, width: int) -> str:
    """Truncate text with ellipsis if longer than width."""
    if len(text) <= width:
        return text
    return text[: width - 1] + "…"


def _format_table(
    headers: list[str],
    rows: list[list[str]],
    color: bool = True,
    col_colors: dict[int, dict[str, str]] | None = None,
) -> str:
    """Render a pretty Unicode-bordered table.

    col_colors: {col_index: {cell_value: ansi_color}} for per-cell coloring.
    """
    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    # Box-drawing characters
    tl, tr, bl, br = "┌", "┐", "└", "┘"
    hz, vt = "─", "│"
    lj, rj, tj, bj, cr = "├", "┤", "┬", "┴", "┼"

    def _hline(left: str, mid: str, right: str) -> str:
        return left + mid.join(hz * (w + 2) for w in widths) + right

    def _row(cells: list[str], raw_cells: list[str] | None = None) -> str:
        """Format a row.  raw_cells = uncolored text for width calc."""
        if raw_cells is None:
            raw_cells = cells
        parts = []
        for i, (cell, raw) in enumerate(zip(cells, raw_cells)):
            pad = widths[i] - len(raw)
            parts.append(f" {cell}{' ' * pad} ")
        return vt + vt.join(parts) + vt

    lines: list[str] = []

    # Top border
    lines.append(_hline(tl, tj, tr))

    # Header
    styled_headers = [
        _c(_C.BOLD, h, color) for h in headers
    ]
    lines.append(_row(styled_headers, headers))
    lines.append(_hline(lj, cr, rj))

    # Data rows
    for row in rows:
        styled = list(row)
        if col_colors and color:
            for col_idx, val_map in col_colors.items():
                if col_idx < len(styled):
                    cell_val = row[col_idx]
                    # Case-insensitive lookup
                    lower_map = {k.lower(): v for k, v in val_map.items()}
                    clr = lower_map.get(cell_val.lower().strip())
                    if clr:
                        styled[col_idx] = _c(clr, cell_val)
        lines.append(_row(styled, row))

    # Bottom border
    lines.append(_hline(bl, bj, br))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CSV export from database
# ---------------------------------------------------------------------------

_EXPORT_COLUMNS = [
    "id",
    "client",
    "domain",
    "verdict",
    "scan_started",
    "scan_finished",
    "scan_duration_s",
    "created_at",
    # Expanded from report_json
    "dns_classification",
    "dns_rcode",
    "dns_records_a",
    "dns_records_aaaa",
    "dns_records_mx",
    "dns_records_ns",
    "dns_records_txt",
    "dns_records_cname",
    "dns_cname_chain",
    "dns_dnssec",
    "whois_registered",
    "whois_registrar",
    "whois_expiry_date",
    "whois_nameservers",
    "icmp_reachable",
    "icmp_latency_ms",
    "open_ports",
    "closed_ports",
    "filtered_ports",
    "tls_handshake_ok",
    "tls_version",
    "tls_cert_cn",
    "tls_issuer",
    "tls_not_after",
    "tls_expired",
    "tls_matches_domain",
    "http_status",
    "http_server",
    "http_redirect",
    "smtp_responsive",
    "smtp_banner",
    "subdomains_found",
    "waf_detected",
    "waf_provider",
    "asn_ip",
    "asn_number",
    "asn_org",
    "asn_country",
    "decommission_likely",
    "reasoning",
]


def _safe_get(d: dict, *keys: str, default: str = "") -> str:
    """Safely traverse nested dict keys."""
    obj: Any = d
    for k in keys:
        if isinstance(obj, dict):
            obj = obj.get(k)
        else:
            return default
    if obj is None:
        return default
    return str(obj)


def _safe_join(d: dict, *keys: str, sep: str = "; ") -> str:
    """Get a list from nested dict and join as string."""
    obj: Any = d
    for k in keys:
        if isinstance(obj, dict):
            obj = obj.get(k)
        else:
            return ""
    if not obj or not isinstance(obj, list):
        return ""
    return sep.join(str(v) for v in obj)


def _flatten_report_row(scan: dict) -> dict[str, str]:
    """Flatten a scan dict (with parsed report_json) into CSV columns."""
    report = scan.get("report", {}) or {}
    dns = report.get("dns") or {}
    whois = report.get("whois") or {}
    icmp = report.get("icmp") or {}
    tls = report.get("tls") or {}
    http = report.get("http") or {}
    smtp = report.get("smtp") or {}
    waf = report.get("waf") or {}
    asn = report.get("asn") or {}
    decom = report.get("decommission") or {}
    records = dns.get("records") or {}

    # Port classification
    ports = report.get("port_probes") or []
    open_p = [str(p.get("port", "")) for p in ports if p.get("state") == "open"]
    closed_p = [str(p.get("port", "")) for p in ports if p.get("state") == "closed"]
    filtered_p = [str(p.get("port", "")) for p in ports if p.get("state") == "filtered"]

    # Subdomains
    subs = report.get("subdomains") or []
    resolved_subs = [s.get("fqdn", "") for s in subs if s.get("resolved")]

    reasoning = report.get("reasoning") or []

    return {
        "id": str(scan.get("id", "")),
        "client": str(scan.get("client", "")),
        "domain": str(scan.get("domain", "")),
        "verdict": str(scan.get("verdict", "")),
        "scan_started": str(scan.get("scan_started") or ""),
        "scan_finished": str(scan.get("scan_finished") or ""),
        "scan_duration_s": str(scan.get("scan_duration_s") or ""),
        "created_at": str(scan.get("created_at", "")),
        # DNS
        "dns_classification": _safe_get(dns, "classification"),
        "dns_rcode": _safe_get(dns, "rcode"),
        "dns_records_a": "; ".join(records.get("A", []) or []),
        "dns_records_aaaa": "; ".join(records.get("AAAA", []) or []),
        "dns_records_mx": "; ".join(records.get("MX", []) or []),
        "dns_records_ns": "; ".join(records.get("NS", []) or []),
        "dns_records_txt": "; ".join(records.get("TXT", []) or []),
        "dns_records_cname": "; ".join(records.get("CNAME", []) or []),
        "dns_cname_chain": "; ".join(dns.get("cname_chain") or []),
        "dns_dnssec": _safe_get(dns, "dnssec_status"),
        # WHOIS
        "whois_registered": _safe_get(whois, "registered"),
        "whois_registrar": _safe_get(whois, "registrar"),
        "whois_expiry_date": _safe_get(whois, "expiry_date"),
        "whois_nameservers": "; ".join(whois.get("nameservers") or []),
        # ICMP
        "icmp_reachable": _safe_get(icmp, "reachable"),
        "icmp_latency_ms": _safe_get(icmp, "latency_ms"),
        # Ports
        "open_ports": "; ".join(open_p),
        "closed_ports": "; ".join(closed_p),
        "filtered_ports": "; ".join(filtered_p),
        # TLS
        "tls_handshake_ok": _safe_get(tls, "handshake_ok"),
        "tls_version": _safe_get(tls, "tls_version"),
        "tls_cert_cn": _safe_get(tls, "cert_cn"),
        "tls_issuer": _safe_get(tls, "issuer"),
        "tls_not_after": _safe_get(tls, "not_after"),
        "tls_expired": _safe_get(tls, "is_expired"),
        "tls_matches_domain": _safe_get(tls, "cert_matches_domain"),
        # HTTP
        "http_status": _safe_get(http, "status_code"),
        "http_server": _safe_get(http, "server_header"),
        "http_redirect": _safe_get(http, "redirect_target"),
        # SMTP
        "smtp_responsive": _safe_get(smtp, "responsive"),
        "smtp_banner": _safe_get(smtp, "banner"),
        # Subdomains
        "subdomains_found": "; ".join(resolved_subs),
        # WAF
        "waf_detected": _safe_get(waf, "detected"),
        "waf_provider": _safe_get(waf, "provider"),
        # ASN
        "asn_ip": _safe_get(asn, "ip"),
        "asn_number": _safe_get(asn, "asn"),
        "asn_org": _safe_get(asn, "asn_org"),
        "asn_country": _safe_get(asn, "country"),
        # Decommission
        "decommission_likely": _safe_get(decom, "likely_decommissioned"),
        # Reasoning
        "reasoning": "; ".join(reasoning),
    }


def export_csv(db: HostprobeDB, path: str, **filters: Any) -> int:
    """Export database scans to a CSV file. Returns number of rows written."""
    # Get all matching lightweight rows for IDs
    rows = db.get_reports(
        client=filters.get("client"),
        domain=filters.get("domain"),
        verdict=filters.get("verdict"),
        limit=filters.get("limit", 100_000),
    )

    if not rows:
        return 0

    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_EXPORT_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # Fetch full report for each scan
            full = db.get_full_report(row["id"])
            if full:
                writer.writerow(_flatten_report_row(full))
            else:
                # Fallback: write what we have
                writer.writerow({
                    "id": str(row["id"]),
                    "client": row["client"],
                    "domain": row["domain"],
                    "verdict": row["verdict"],
                    "scan_started": str(row.get("scan_started") or ""),
                    "scan_finished": str(row.get("scan_finished") or ""),
                    "scan_duration_s": str(row.get("scan_duration_s") or ""),
                    "created_at": str(row.get("created_at", "")),
                })

    return len(rows)


def export_csv_stdout(db: HostprobeDB, **filters: Any) -> int:
    """Export database scans as CSV to stdout. Returns row count."""
    rows = db.get_reports(
        client=filters.get("client"),
        domain=filters.get("domain"),
        verdict=filters.get("verdict"),
        limit=filters.get("limit", 100_000),
    )

    if not rows:
        return 0

    writer = csv.DictWriter(sys.stdout, fieldnames=_EXPORT_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        full = db.get_full_report(row["id"])
        if full:
            writer.writerow(_flatten_report_row(full))

    return len(rows)


# ---------------------------------------------------------------------------
# Pretty-print commands
# ---------------------------------------------------------------------------

def _print_scans_table(
    db: HostprobeDB,
    client: str | None = None,
    domain: str | None = None,
    verdict: str | None = None,
    limit: int = 50,
) -> int:
    """Print a table of scans. Returns the number of rows printed."""
    color = _use_color()
    rows = db.get_reports(
        client=client, domain=domain, verdict=verdict, limit=limit
    )

    if not rows:
        msg = "No scans found"
        filters = []
        if client:
            filters.append(f"client={client}")
        if domain:
            filters.append(f"domain={domain}")
        if verdict:
            filters.append(f"verdict={verdict}")
        if filters:
            msg += f" ({', '.join(filters)})"
        sys.stderr.write(f"  {msg}\n")
        return 0

    total = db.count_scans(client=client, domain=domain, verdict=verdict)

    # Build table data
    headers = ["ID", "CLIENT", "DOMAIN", "VERDICT", "SCANNED", "DURATION"]
    table_rows: list[list[str]] = []
    for r in rows:
        scan_time = r.get("scan_started") or r.get("created_at") or ""
        # Trim to just date+time (no microseconds)
        if scan_time and len(scan_time) > 19:
            scan_time = scan_time[:19]
        duration = f"{r['scan_duration_s']:.1f}s" if r.get("scan_duration_s") else "—"
        table_rows.append([
            str(r["id"]),
            _truncate(r["client"], 20),
            _truncate(r["domain"], 35),
            r["verdict"].upper().replace("_", " "),
            scan_time,
            duration,
        ])

    # Verdict coloring on column index 3
    verdict_colors = {
        "ALIVE": _C.GREEN,
        "LIKELY DEAD": _C.RED,
        "FILTERED": _C.YELLOW,
        "PARTIAL": _C.YELLOW,
        "INVESTIGATE": _C.MAGENTA,
        "RECENTLY DECOMMISSIONED": _C.CYAN,
    }

    table = _format_table(
        headers,
        table_rows,
        color=color,
        col_colors={3: verdict_colors},
    )
    sys.stdout.write(table + "\n")

    if total > limit:
        sys.stderr.write(
            f"  Showing {len(rows)} of {total} scans (use --limit to see more)\n"
        )
    else:
        sys.stderr.write(f"  {total} scan(s) total\n")

    return len(rows)


def _print_clients_table(db: HostprobeDB) -> int:
    """Print a table of clients with scan counts."""
    color = _use_color()
    clients = db.list_clients()

    if not clients:
        sys.stderr.write("  No clients found in database.\n")
        return 0

    headers = ["ID", "CLIENT", "SCANS", "LAST SCAN", "CREATED"]
    table_rows: list[list[str]] = []
    for c in clients:
        last_scan = c.get("last_scan") or "—"
        if last_scan != "—" and len(last_scan) > 19:
            last_scan = last_scan[:19]
        created = c.get("created_at") or ""
        if created and len(created) > 19:
            created = created[:19]
        table_rows.append([
            str(c["id"]),
            c["name"],
            str(c["scan_count"]),
            last_scan,
            created,
        ])

    table = _format_table(headers, table_rows, color=color)
    sys.stdout.write(table + "\n")
    sys.stderr.write(f"  {len(clients)} client(s)\n")
    return len(clients)


def _print_full_report(db: HostprobeDB, scan_id: int) -> bool:
    """Print the full JSON report for a given scan ID."""
    color = _use_color()
    full = db.get_full_report(scan_id)
    if not full:
        sys.stderr.write(f"  Scan ID {scan_id} not found.\n")
        return False

    report = full.get("report", {})

    # Header
    client_name = full["client"]
    domain_name = full["domain"]
    header = (
        f"\n  {_c(_C.BOLD, f'Scan #{scan_id}', color)}"
        f"  {_c(_C.DIM, f'Client: {client_name}', color)}"
        f"  {_c(_C.DIM, f'Domain: {domain_name}', color)}"
    )
    sys.stdout.write(header + "\n")

    # Pretty-print the JSON
    formatted = json.dumps(report, indent=2, default=str)
    sys.stdout.write(formatted + "\n")
    return True


def _print_domain_history(db: HostprobeDB, domain: str, client: str | None = None) -> int:
    """Print scan history for a specific domain."""
    color = _use_color()
    rows = db.get_domain_history(domain, client=client)

    if not rows:
        sys.stderr.write(f"  No history found for {domain}\n")
        return 0

    sys.stdout.write(
        f"\n  {_c(_C.BOLD, f'History for {domain}', color)} — {len(rows)} scan(s)\n\n"
    )

    headers = ["ID", "CLIENT", "VERDICT", "SCANNED", "DURATION"]
    table_rows: list[list[str]] = []
    for r in rows:
        scan_time = r.get("scan_started") or r.get("created_at") or ""
        if scan_time and len(scan_time) > 19:
            scan_time = scan_time[:19]
        duration = f"{r['scan_duration_s']:.1f}s" if r.get("scan_duration_s") else "—"
        table_rows.append([
            str(r["id"]),
            _truncate(r["client"], 20),
            r["verdict"].upper().replace("_", " "),
            scan_time,
            duration,
        ])

    verdict_colors = {
        "ALIVE": _C.GREEN,
        "LIKELY DEAD": _C.RED,
        "FILTERED": _C.YELLOW,
        "PARTIAL": _C.YELLOW,
        "INVESTIGATE": _C.MAGENTA,
        "RECENTLY DECOMMISSIONED": _C.CYAN,
    }

    table = _format_table(
        headers,
        table_rows,
        color=color,
        col_colors={2: verdict_colors},
    )
    sys.stdout.write(table + "\n")
    return len(rows)


# ---------------------------------------------------------------------------
# Dump: detailed pretty table with ALL fields per scan
# ---------------------------------------------------------------------------

# Section definitions: (section_label, [(display_label, flat_key), ...])
_DUMP_SECTIONS: list[tuple[str, list[tuple[str, str]]]] = [
    ("GENERAL", [
        ("ID", "id"),
        ("Client", "client"),
        ("Domain", "domain"),
        ("Verdict", "verdict"),
        ("Scan Started", "scan_started"),
        ("Scan Finished", "scan_finished"),
        ("Duration", "scan_duration_s"),
        ("Stored At", "created_at"),
    ]),
    ("DNS", [
        ("Classification", "dns_classification"),
        ("Response Code", "dns_rcode"),
        ("DNSSEC", "dns_dnssec"),
        ("A Records", "dns_records_a"),
        ("AAAA Records", "dns_records_aaaa"),
        ("MX Records", "dns_records_mx"),
        ("NS Records", "dns_records_ns"),
        ("TXT Records", "dns_records_txt"),
        ("CNAME Records", "dns_records_cname"),
        ("CNAME Chain", "dns_cname_chain"),
    ]),
    ("WHOIS", [
        ("Registered", "whois_registered"),
        ("Registrar", "whois_registrar"),
        ("Expiry Date", "whois_expiry_date"),
        ("Nameservers", "whois_nameservers"),
    ]),
    ("CONNECTIVITY", [
        ("ICMP Reachable", "icmp_reachable"),
        ("ICMP Latency", "icmp_latency_ms"),
        ("Open Ports", "open_ports"),
        ("Closed Ports", "closed_ports"),
        ("Filtered Ports", "filtered_ports"),
    ]),
    ("TLS", [
        ("Handshake OK", "tls_handshake_ok"),
        ("Version", "tls_version"),
        ("Cert CN", "tls_cert_cn"),
        ("Issuer", "tls_issuer"),
        ("Not After", "tls_not_after"),
        ("Expired", "tls_expired"),
        ("Matches Domain", "tls_matches_domain"),
    ]),
    ("HTTP", [
        ("Status", "http_status"),
        ("Server", "http_server"),
        ("Redirect", "http_redirect"),
    ]),
    ("SMTP", [
        ("Responsive", "smtp_responsive"),
        ("Banner", "smtp_banner"),
    ]),
    ("WAF / FIREWALL", [
        ("Detected", "waf_detected"),
        ("Provider", "waf_provider"),
    ]),
    ("ASN / GEO", [
        ("IP", "asn_ip"),
        ("ASN", "asn_number"),
        ("Organization", "asn_org"),
        ("Country", "asn_country"),
    ]),
    ("SUBDOMAINS", [
        ("Found", "subdomains_found"),
    ]),
    ("DECOMMISSION", [
        ("Likely", "decommission_likely"),
    ]),
    ("REASONING", [
        ("Reasoning", "reasoning"),
    ]),
]


def _print_dump_card(flat: dict[str, str], color: bool) -> str:
    """Render a single scan as a vertical key-value card."""
    lines: list[str] = []
    sep = _c(_C.DIM, "━" * 72, color)

    # Title bar
    domain = flat.get("domain", "?")
    scan_id = flat.get("id", "?")
    client = flat.get("client", "?")
    verdict = flat.get("verdict", "?").upper().replace("_", " ")

    verdict_clr = {
        "ALIVE": _C.GREEN, "LIKELY DEAD": _C.RED, "FILTERED": _C.YELLOW,
        "PARTIAL": _C.YELLOW, "INVESTIGATE": _C.MAGENTA,
        "RECENTLY DECOMMISSIONED": _C.CYAN,
    }.get(verdict, _C.WHITE)

    lines.append("")
    lines.append(sep)
    lines.append(
        f"  {_c(_C.BOLD, f'#{scan_id}', color)}"
        f"  {_c(_C.BOLD, domain, color)}"
        f"  {_c(verdict_clr + _C.BOLD, verdict, color)}"
        f"  {_c(_C.DIM, f'({client})', color)}"
    )
    lines.append(sep)

    for section_label, fields in _DUMP_SECTIONS:
        # Gather non-empty values for this section
        section_rows: list[tuple[str, str]] = []
        for display_label, key in fields:
            val = flat.get(key, "")
            if val and val not in ("", "None", "False"):
                section_rows.append((display_label, val))

        if not section_rows:
            continue

        # Section header
        lines.append(f"  {_c(_C.BOLD + _C.BLUE, f'[{section_label}]', color)}")

        label_width = max(len(lbl) for lbl, _ in section_rows)
        for label, value in section_rows:
            # Color special values
            display_val = value
            if key == "verdict":
                pass  # already in header
            elif value.lower() == "true":
                display_val = _c(_C.GREEN, value, color)
            elif value.lower() == "false":
                display_val = _c(_C.RED, value, color)

            # Wrap long values
            max_val_width = 58
            if len(value) > max_val_width:
                # Multi-line: first line + continuation
                chunks = [value[i:i + max_val_width] for i in range(0, len(value), max_val_width)]
                lines.append(f"    {label:<{label_width}s} : {chunks[0]}")
                for chunk in chunks[1:]:
                    lines.append(f"    {' ' * label_width}   {chunk}")
            else:
                lines.append(f"    {label:<{label_width}s} : {display_val}")

        lines.append("")  # blank line between sections

    return "\n".join(lines)


def _print_dump(
    db: HostprobeDB,
    client: str | None = None,
    domain: str | None = None,
    verdict: str | None = None,
    limit: int = 50,
) -> int:
    """Print a full data dump with all fields in pretty vertical cards."""
    color = _use_color()
    rows = db.get_reports(
        client=client, domain=domain, verdict=verdict, limit=limit
    )

    if not rows:
        msg = "No scans found"
        flt = []
        if client:
            flt.append(f"client={client}")
        if domain:
            flt.append(f"domain={domain}")
        if verdict:
            flt.append(f"verdict={verdict}")
        if flt:
            msg += f" ({', '.join(flt)})"
        sys.stderr.write(f"  {msg}\n")
        return 0

    total = db.count_scans(client=client, domain=domain, verdict=verdict)
    count = 0

    for row in rows:
        full = db.get_full_report(row["id"])
        if full:
            flat = _flatten_report_row(full)
            sys.stdout.write(_print_dump_card(flat, color) + "\n")
            count += 1

    if total > limit:
        sys.stderr.write(
            f"\n  Showing {count} of {total} scans (use --limit to see more)\n"
        )
    else:
        sys.stderr.write(f"\n  {count} scan(s) dumped\n")

    return count


# ---------------------------------------------------------------------------
# Argument parser & entry point
# ---------------------------------------------------------------------------

def build_db_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the db subcommand."""
    parser = argparse.ArgumentParser(
        prog="hostprobe db",
        description=(
            "Query and export hostprobe scan results from the SQLite database.\n"
            "Displays results in a pretty table or exports to CSV."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  hostprobe db results.db                         # summary table\n"
            "  hostprobe db results.db --dump                  # ALL data, pretty cards\n"
            "  hostprobe db results.db --client acme           # filter by client\n"
            "  hostprobe db results.db --verdict alive          # filter by verdict\n"
            "  hostprobe db results.db --export-csv out.csv    # export ALL to CSV\n"
            "  hostprobe db results.db --dump --export-csv o.csv  # both at once\n"
            "  hostprobe db results.db --clients               # list clients\n"
            "  hostprobe db results.db --full 42               # full JSON for scan #42\n"
            "  hostprobe db results.db --history example.com   # domain scan history\n"
        ),
    )

    parser.add_argument(
        "db_path",
        help="Path to the SQLite database file",
    )

    # View modes
    view_group = parser.add_argument_group("view")
    view_group.add_argument(
        "--dump",
        action="store_true",
        help="Show ALL data fields in detailed pretty cards per scan",
    )
    view_group.add_argument(
        "--clients",
        action="store_true",
        help="List all clients with scan counts",
    )
    view_group.add_argument(
        "--full",
        type=int,
        metavar="SCAN_ID",
        help="Show full JSON report for a specific scan ID",
    )
    view_group.add_argument(
        "--history",
        type=str,
        metavar="DOMAIN",
        help="Show scan history for a specific domain",
    )

    # Filters
    filter_group = parser.add_argument_group("filters")
    filter_group.add_argument(
        "--client",
        type=str,
        help="Filter results by client name",
    )
    filter_group.add_argument(
        "--domain",
        type=str,
        help="Filter results by domain",
    )
    filter_group.add_argument(
        "--verdict",
        type=str,
        choices=[
            "alive", "likely_dead", "filtered",
            "partial", "investigate", "recently_decommissioned",
        ],
        help="Filter results by verdict",
    )
    filter_group.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum rows to display (default: 50)",
    )

    # Export
    export_group = parser.add_argument_group("export")
    export_group.add_argument(
        "--export-csv",
        type=str,
        metavar="FILE",
        help="Export all matching scans to a CSV file (use '-' for stdout)",
    )

    return parser


def db_main(argv: list[str]) -> None:
    """Entry point for the `hostprobe db` subcommand."""
    parser = build_db_parser()
    args = parser.parse_args(argv)

    db_path = Path(args.db_path)
    if not db_path.exists():
        sys.stderr.write(f"  Error: database not found: {args.db_path}\n")
        sys.exit(1)

    with HostprobeDB(args.db_path) as db:
        filters = {
            "client": args.client,
            "domain": args.domain,
            "verdict": args.verdict,
            "limit": args.limit,
        }

        # Handle --dump + --export-csv together ("both")
        ok = True

        if args.dump:
            count = _print_dump(
                db,
                client=args.client,
                domain=args.domain,
                verdict=args.verdict,
                limit=args.limit,
            )
            ok = count > 0

        if args.export_csv:
            if args.export_csv == "-":
                count = export_csv_stdout(db, **filters)
            else:
                count = export_csv(db, args.export_csv, **filters)
                if count:
                    sys.stderr.write(f"  Exported {count} scan(s) to {args.export_csv}\n")
                else:
                    sys.stderr.write("  No scans found to export.\n")
            ok = ok and count > 0

        if args.dump or args.export_csv:
            sys.exit(0 if ok else 1)

        # View modes
        if args.clients:
            _print_clients_table(db)
            sys.exit(0)

        if args.full is not None:
            ok = _print_full_report(db, args.full)
            sys.exit(0 if ok else 1)

        if args.history:
            count = _print_domain_history(db, args.history, client=args.client)
            sys.exit(0 if count else 1)

        # Default: show scans table
        _print_scans_table(
            db,
            client=args.client,
            domain=args.domain,
            verdict=args.verdict,
            limit=args.limit,
        )
        sys.exit(0)
