"""Output formatting: JSON, CSV, and ANSI-colored terminal output."""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import sys
import time
from datetime import datetime
from enum import Enum
from typing import Any

from hostprobe.models import (
    DomainReport,
    PortState,
    Verdict,
)


# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

class _Colors:
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
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


def _supports_color() -> bool:
    """Check if stderr supports ANSI color."""
    if not hasattr(sys.stderr, "isatty"):
        return False
    return sys.stderr.isatty()


C = _Colors


def _c(color: str, text: str, use_color: bool = True) -> str:
    """Wrap text in color codes if color is enabled."""
    if use_color:
        return f"{color}{text}{C.RESET}"
    return text


# ---------------------------------------------------------------------------
# Verdict coloring
# ---------------------------------------------------------------------------

VERDICT_COLORS = {
    Verdict.ALIVE: C.GREEN,
    Verdict.LIKELY_DEAD: C.RED,
    Verdict.FILTERED: C.YELLOW,
    Verdict.PARTIAL: C.YELLOW,
    Verdict.INVESTIGATE: C.MAGENTA,
    Verdict.RECENTLY_DECOMMISSIONED: C.CYAN,
}

VERDICT_ICONS = {
    Verdict.ALIVE: "[+]",
    Verdict.LIKELY_DEAD: "[-]",
    Verdict.FILTERED: "[?]",
    Verdict.PARTIAL: "[~]",
    Verdict.INVESTIGATE: "[!]",
    Verdict.RECENTLY_DECOMMISSIONED: "[x]",
}


# ---------------------------------------------------------------------------
# Progress Callback (writes to stderr)
# ---------------------------------------------------------------------------

class TerminalProgress:
    """Progress reporter that writes phase updates to stderr."""

    def __init__(self, domain: str, use_color: bool = True, quiet: bool = False):
        self.domain = domain
        self.use_color = use_color
        self.quiet = quiet

    def phase(self, phase_name: str, detail: str = "") -> None:
        if self.quiet:
            return
        label = _c(C.DIM, f"[{phase_name.upper():>12}]", self.use_color)
        msg = f"  {label} {detail}"
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()

    def done(self) -> None:
        pass


class BatchProgress:
    """Progress reporter for batch mode with ETA."""

    def __init__(self, total: int, use_color: bool = True, quiet: bool = False):
        self.total = total
        self.current = 0
        self.use_color = use_color
        self.quiet = quiet
        self._start = time.monotonic()

    def start_domain(self, domain: str) -> TerminalProgress:
        self.current += 1
        if not self.quiet:
            counter = _c(C.BOLD, f"[{self.current}/{self.total}]", self.use_color)
            elapsed = time.monotonic() - self._start
            eta = ""
            if self.current > 1:
                avg = elapsed / (self.current - 1)
                remaining = avg * (self.total - self.current + 1)
                eta = f"  ETA {remaining:.0f}s"
            sys.stderr.write(f"\n{counter} Scanning {domain}{eta}\n")
            sys.stderr.flush()
        return TerminalProgress(domain, self.use_color, self.quiet)

    def summary(self) -> None:
        """Print final summary line after all domains are processed."""
        if self.quiet:
            return
        elapsed = time.monotonic() - self._start
        sys.stderr.write(
            f"\n{_c(C.GREEN, '✓', self.use_color)} "
            f"Completed {self.total} domain(s) in {elapsed:.1f}s\n"
        )
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# Terminal Formatter
# ---------------------------------------------------------------------------

def format_terminal(report: DomainReport, use_color: bool | None = None) -> str:
    """Format a DomainReport as a colored terminal string."""
    if use_color is None:
        use_color = _supports_color()

    lines: list[str] = []
    _sep = _c(C.DIM, "─" * 60, use_color)

    # Header
    lines.append("")
    lines.append(_sep)
    lines.append(_c(C.BOLD, f"  HOSTPROBE REPORT: {report.domain}", use_color))
    lines.append(_sep)

    # DNS
    if report.dns:
        dns = report.dns
        cls_color = C.GREEN if dns.classification.value == "resolved" else C.RED
        lines.append(_section("DNS", use_color))
        lines.append(f"  Classification : {_c(cls_color, dns.classification.value.upper(), use_color)}")
        lines.append(f"  Response Code  : {dns.rcode}")
        lines.append(f"  Resolvers      : {', '.join(dns.resolvers_queried)}")
        lines.append(f"  Authoritative  : {'Yes' if dns.authoritative else 'No'}")
        lines.append(f"  DNSSEC         : {dns.dnssec_status}")

        if dns.cname_chain:
            lines.append(f"  CNAME Chain    : {report.domain} → {' → '.join(dns.cname_chain)}")

        # Records table
        has_records = any(v for v in dns.records.values())
        if has_records:
            lines.append("")
            lines.append(_section("RECORDS", use_color))
            for rtype, vals in sorted(dns.records.items()):
                if vals:
                    for val in vals:
                        lines.append(f"  {rtype:6s} : {val}")

    # WHOIS
    if report.whois:
        w = report.whois
        lines.append("")
        lines.append(_section("WHOIS", use_color))
        reg_color = C.GREEN if w.registered else C.RED
        lines.append(f"  Registered     : {_c(reg_color, str(w.registered), use_color)}")
        if w.registrar:
            lines.append(f"  Registrar      : {w.registrar}")
        if w.expiry_date:
            exp_str = w.expiry_date.strftime("%Y-%m-%d")
            if w.recently_expired:
                exp_str += _c(C.YELLOW, " (RECENTLY EXPIRED)", use_color)
            lines.append(f"  Expires        : {exp_str}")
        if w.nameservers:
            lines.append(f"  Nameservers    : {', '.join(w.nameservers[:4])}")

    # Subdomains
    resolved_subs = [s for s in report.subdomains if s.resolved]
    if resolved_subs:
        lines.append("")
        lines.append(_section("SUBDOMAINS", use_color))
        for sub in resolved_subs[:15]:
            addrs = ", ".join(sub.addresses) if sub.addresses else ""
            cname = f" → CNAME {sub.cname_target}" if sub.cname_target else ""
            lines.append(f"  {_c(C.GREEN, '✓', use_color)} {sub.fqdn:30s} {addrs}{cname}")
        if len(resolved_subs) > 15:
            lines.append(f"  ... and {len(resolved_subs) - 15} more")

    # Passive Recon
    if report.passive:
        p = report.passive
        lines.append("")
        lines.append(_section("PASSIVE", use_color))
        if p.ct_entries:
            recent = sum(1 for e in p.ct_entries if e.is_recent)
            lines.append(f"  CT Entries     : {len(p.ct_entries)} total, {recent} recent (<90d)")
            # Show most recent 3
            sorted_entries = sorted(
                [e for e in p.ct_entries if e.not_before],
                key=lambda e: e.not_before or datetime.min,
                reverse=True,
            )
            for entry in sorted_entries[:3]:
                date_str = entry.not_before.strftime("%Y-%m-%d") if entry.not_before else "?"
                lines.append(f"    {date_str}  {entry.common_name}")
        else:
            lines.append(f"  CT Entries     : none found")
        if p.passive_dns_hits:
            lines.append(f"  Passive DNS    : {len(p.passive_dns_hits)} hit(s)")
        if p.discovered_subdomains:
            lines.append(f"  Discovered     : {len(p.discovered_subdomains)} subdomain(s) from passive sources")

    # ICMP
    if report.icmp:
        lines.append("")
        lines.append(_section("ICMP", use_color))
        if report.icmp.reachable:
            lines.append(f"  Ping           : {_c(C.GREEN, 'reachable', use_color)} ({report.icmp.latency_ms}ms)")
        else:
            lines.append(f"  Ping           : {_c(C.YELLOW, 'no response', use_color)}")

    # Ports
    if report.port_probes:
        lines.append("")
        lines.append(_section("PORTS", use_color))
        for pp in report.port_probes:
            state_color = {
                PortState.OPEN: C.GREEN,
                PortState.CLOSED: C.YELLOW,
                PortState.FILTERED: C.RED,
                PortState.ERROR: C.RED,
            }.get(pp.state, C.WHITE)
            latency = f" ({pp.latency_ms}ms)" if pp.latency_ms else ""
            method = f" [{pp.method}]" if pp.method != "connect" else ""
            state_str = f"{pp.state.value.upper():<8s}"
            lines.append(
                f"  {pp.port:5d}/tcp : {_c(state_color, state_str, use_color)}{latency}{method}"
            )

    # TLS
    if report.tls and report.tls.handshake_ok:
        t = report.tls
        lines.append("")
        lines.append(_section("TLS", use_color))
        lines.append(f"  Version        : {t.tls_version or '?'}")
        lines.append(f"  CN             : {t.cert_cn or '?'}")
        if t.cert_san_list:
            lines.append(f"  SANs           : {', '.join(t.cert_san_list[:5])}")
        lines.append(f"  Issuer         : {t.issuer or '?'}")
        if t.not_after:
            exp_str = t.not_after.strftime("%Y-%m-%d")
            if t.is_expired:
                exp_str = _c(C.RED, f"{exp_str} EXPIRED", use_color)
            elif t.expires_soon:
                exp_str = _c(C.YELLOW, f"{exp_str} (expires soon)", use_color)
            lines.append(f"  Expires        : {exp_str}")
        match_str = _c(C.GREEN, "Yes", use_color) if t.cert_matches_domain else _c(C.RED, "No", use_color)
        lines.append(f"  Matches Domain : {match_str}")
    elif report.tls and not report.tls.handshake_ok:
        lines.append("")
        lines.append(_section("TLS", use_color))
        reason = report.tls.error_reason or "unknown"
        lines.append(f"  Handshake      : {_c(C.RED, f'FAILED ({reason})', use_color)}")

    # SMTP
    if report.smtp and report.smtp.responsive:
        lines.append("")
        lines.append(_section("SMTP", use_color))
        lines.append(f"  Banner         : {report.smtp.banner[:80]}")
        lines.append(f"  STARTTLS       : {'Yes' if report.smtp.supports_starttls else 'No'}")

    # HTTP
    if report.http and report.http.status_code:
        h = report.http
        lines.append("")
        lines.append(_section("HTTP", use_color))
        lines.append(f"  Status         : {h.status_code}")
        lines.append(f"  Server         : {h.server_header or '?'}")
        if h.redirect_target:
            lines.append(f"  Redirect       : {h.redirect_target}")

    # Banners
    if report.banners:
        lines.append("")
        lines.append(_section("BANNERS", use_color))
        for b in report.banners:
            lines.append(f"  {b.port}/tcp : {b.banner_text[:60]} ({b.protocol_guess or '?'})")

    # Edge Cases
    edge = report.edge_cases
    edge_items: list[str] = []
    if edge.is_wildcard:
        edge_items.append(_c(C.YELLOW, "Wildcard DNS", use_color))
    if edge.is_cdn:
        edge_items.append(f"CDN: {edge.cdn_provider}")
    if edge.cloud_provider:
        edge_items.append(f"Cloud: {edge.cloud_provider}")
    if edge.has_ipv6:
        v6_status = _c(C.GREEN, "reachable", use_color) if edge.ipv6_reachable else "AAAA only"
        edge_items.append(f"IPv6: {v6_status}")
    if edge.split_horizon_mismatch:
        edge_items.append(_c(C.YELLOW, "Split-horizon mismatch", use_color))
    if edge.dangling_cnames:
        edge_items.append(_c(C.RED, f"{len(edge.dangling_cnames)} dangling CNAME(s)", use_color))

    if edge_items:
        lines.append("")
        lines.append(_section("EDGE CASES", use_color))
        for item in edge_items:
            lines.append(f"  • {item}")
        for dc in edge.dangling_cnames:
            lines.append(f"    {_c(C.RED, dc, use_color)}")
        for artifact in edge.cloud_artifacts:
            lines.append(f"    {artifact}")

    # WAF
    if report.waf and report.waf.detected:
        lines.append("")
        lines.append(_section("WAF / FIREWALL", use_color))
        lines.append(f"  Provider       : {_c(C.YELLOW, report.waf.provider or '?', use_color)}")
        if report.waf.is_blocking:
            lines.append(f"  Status         : {_c(C.RED, 'BLOCKING', use_color)}")
        for ev in report.waf.evidence[:5]:
            lines.append(f"    {ev}")

    # ASN / Geolocation
    if report.asn and report.asn.asn:
        lines.append("")
        lines.append(_section("ASN / GEO", use_color))
        lines.append(f"  IP             : {report.asn.ip}")
        lines.append(f"  ASN            : AS{report.asn.asn} ({report.asn.asn_org or '?'})")
        if report.asn.isp:
            lines.append(f"  ISP            : {report.asn.isp}")
        loc_parts = [p for p in [report.asn.city, report.asn.country] if p]
        if loc_parts:
            lines.append(f"  Location       : {', '.join(loc_parts)}")
        if report.asn.is_cloud:
            lines.append(f"  Cloud          : {_c(C.CYAN, report.asn.cloud_provider or '?', use_color)}")

    # Decommission
    if report.decommission and report.decommission.likely_decommissioned:
        lines.append("")
        lines.append(_section("DECOMMISSION", use_color))
        for ev in report.decommission.evidence:
            lines.append(f"  • {ev}")

    # Verdict
    lines.append("")
    lines.append(_sep)
    v = report.verdict
    v_color = VERDICT_COLORS.get(v, C.WHITE)
    v_icon = VERDICT_ICONS.get(v, "[?]")
    verdict_label = v.value.upper().replace("_", " ")
    lines.append(
        f"  {_c(C.BOLD + v_color, f'{v_icon} VERDICT: {verdict_label}', use_color)}"
    )
    lines.append(_sep)

    # Reasoning
    lines.append("")
    lines.append(_c(C.DIM, "  Reasoning:", use_color))
    for reason in report.reasoning:
        if reason.startswith("VERDICT") or reason.startswith("STOP"):
            lines.append(f"  {_c(C.BOLD, f'→ {reason}', use_color)}")
        elif reason.startswith("WARNING") or reason.startswith("DANGLING"):
            lines.append(f"  {_c(C.YELLOW, f'⚠ {reason}', use_color)}")
        elif reason.startswith("  "):
            lines.append(f"     {reason.strip()}")
        else:
            lines.append(f"  • {reason}")

    # Timing
    if report.scan_duration_s is not None:
        lines.append("")
        lines.append(_c(C.DIM, f"  Scan completed in {report.scan_duration_s}s", use_color))

    lines.append("")
    return "\n".join(lines)


def format_verdict_line(report: DomainReport, use_color: bool | None = None) -> str:
    """Single-line verdict for --quiet mode."""
    if use_color is None:
        use_color = _supports_color()
    v = report.verdict
    v_color = VERDICT_COLORS.get(v, C.WHITE)
    v_icon = VERDICT_ICONS.get(v, "[?]")
    verdict_str = v.value.upper().replace("_", " ")
    return _c(C.BOLD + v_color, f"{v_icon} {report.domain}: {verdict_str}", use_color)


def _section(name: str, use_color: bool) -> str:
    """Format a section header."""
    return _c(C.BOLD + C.BLUE, f"  [{name}]", use_color)


# ---------------------------------------------------------------------------
# JSON Formatter
# ---------------------------------------------------------------------------

class _ReportEncoder(json.JSONEncoder):
    """Custom JSON encoder for DomainReport dataclasses."""

    def default(self, o: Any) -> Any:
        if isinstance(o, Enum):
            return o.value
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, set):
            return sorted(o)
        if dataclasses.is_dataclass(o) and not isinstance(o, type):
            return _dc_to_dict(o)
        return super().default(o)


def _dc_to_dict(obj: Any) -> Any:
    """Convert a dataclass to a dict, handling enums, datetimes, and sets."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        result = {}
        for f in dataclasses.fields(obj):
            val = getattr(obj, f.name)
            result[f.name] = _dc_to_dict(val)
        return result
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    if isinstance(obj, list):
        return [_dc_to_dict(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _dc_to_dict(v) for k, v in obj.items()}
    return obj


def format_json(report: DomainReport | list[DomainReport], indent: int = 2) -> str:
    """Serialize a DomainReport (or list) to JSON."""
    if isinstance(report, DomainReport):
        data = _dc_to_dict(report)
    else:
        data = [_dc_to_dict(r) for r in report]
    return json.dumps(data, cls=_ReportEncoder, indent=indent, default=str)


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "domain",
    "verdict",
    "reasoning",
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
    "whois_creation_date",
    "whois_expiry_date",
    "whois_nameservers",
    "whois_recently_expired",
    "icmp_reachable",
    "icmp_latency_ms",
    "open_ports",
    "closed_ports",
    "filtered_ports",
    "tls_handshake_ok",
    "tls_version",
    "tls_cert_cn",
    "tls_cert_san",
    "tls_issuer",
    "tls_not_before",
    "tls_not_after",
    "tls_expired",
    "tls_matches_domain",
    "tls_error_reason",
    "http_status",
    "http_server",
    "http_redirect",
    "smtp_responsive",
    "smtp_banner",
    "smtp_starttls",
    "subdomains_found",
    "ct_entries_count",
    "ct_recent_count",
    "passive_dns_hits",
    "is_wildcard",
    "is_cdn",
    "cdn_provider",
    "cloud_provider",
    "cloud_artifacts",
    "has_ipv6",
    "ipv6_reachable",
    "split_horizon_mismatch",
    "dangling_cnames",
    "decommission_likely",
    "decommission_evidence",
    "waf_detected",
    "waf_provider",
    "waf_blocking",
    "waf_evidence",
    "asn_ip",
    "asn_number",
    "asn_org",
    "asn_isp",
    "asn_country",
    "asn_city",
    "asn_is_cloud",
    "asn_cloud_provider",
    "scan_started",
    "scan_finished",
    "scan_duration_s",
]


def _report_to_csv_row(report: DomainReport) -> dict[str, str]:
    """Flatten a DomainReport into a dict of strings keyed by CSV column."""

    def _join(items: list | set | None, sep: str = "; ") -> str:
        if not items:
            return ""
        return sep.join(str(i) for i in items)

    def _dt(d: datetime | None) -> str:
        return d.isoformat() if d else ""

    def _records(rtype: str) -> str:
        if not report.dns:
            return ""
        return _join(report.dns.records.get(rtype, []))

    # Port states
    open_ports: list[str] = []
    closed_ports: list[str] = []
    filtered_ports: list[str] = []
    for p in report.port_probes:
        if p.state == PortState.OPEN:
            open_ports.append(str(p.port))
        elif p.state == PortState.CLOSED:
            closed_ports.append(str(p.port))
        elif p.state == PortState.FILTERED:
            filtered_ports.append(str(p.port))

    # Subdomains that resolved
    resolved_subs = [s.fqdn for s in report.subdomains if s.resolved]

    # CT entries
    ct_count = len(report.passive.ct_entries) if report.passive else 0
    ct_recent = sum(1 for e in (report.passive.ct_entries if report.passive else []) if e.is_recent)

    row: dict[str, str] = {
        "domain": report.domain,
        "verdict": report.verdict.value,
        "reasoning": _join(report.reasoning),
        # DNS
        "dns_classification": report.dns.classification.value if report.dns else "",
        "dns_rcode": report.dns.rcode if report.dns else "",
        "dns_records_a": _records("A"),
        "dns_records_aaaa": _records("AAAA"),
        "dns_records_mx": _records("MX"),
        "dns_records_ns": _records("NS"),
        "dns_records_txt": _records("TXT"),
        "dns_records_cname": _records("CNAME"),
        "dns_cname_chain": _join(report.dns.cname_chain) if report.dns else "",
        "dns_dnssec": report.dns.dnssec_status if report.dns else "",
        # WHOIS
        "whois_registered": str(report.whois.registered) if report.whois else "",
        "whois_registrar": report.whois.registrar or "" if report.whois else "",
        "whois_creation_date": _dt(report.whois.creation_date) if report.whois else "",
        "whois_expiry_date": _dt(report.whois.expiry_date) if report.whois else "",
        "whois_nameservers": _join(report.whois.nameservers) if report.whois else "",
        "whois_recently_expired": str(report.whois.recently_expired) if report.whois else "",
        # ICMP
        "icmp_reachable": str(report.icmp.reachable) if report.icmp else "",
        "icmp_latency_ms": str(report.icmp.latency_ms) if report.icmp and report.icmp.latency_ms else "",
        # Ports
        "open_ports": _join(open_ports),
        "closed_ports": _join(closed_ports),
        "filtered_ports": _join(filtered_ports),
        # TLS
        "tls_handshake_ok": str(report.tls.handshake_ok) if report.tls else "",
        "tls_version": report.tls.tls_version or "" if report.tls else "",
        "tls_cert_cn": report.tls.cert_cn or "" if report.tls else "",
        "tls_cert_san": _join(report.tls.cert_san_list) if report.tls else "",
        "tls_issuer": report.tls.issuer or "" if report.tls else "",
        "tls_not_before": _dt(report.tls.not_before) if report.tls else "",
        "tls_not_after": _dt(report.tls.not_after) if report.tls else "",
        "tls_expired": str(report.tls.is_expired) if report.tls else "",
        "tls_matches_domain": str(report.tls.cert_matches_domain) if report.tls else "",
        "tls_error_reason": report.tls.error_reason or "" if report.tls else "",
        # HTTP
        "http_status": str(report.http.status_code) if report.http and report.http.status_code else "",
        "http_server": report.http.server_header or "" if report.http else "",
        "http_redirect": report.http.redirect_target or "" if report.http else "",
        # SMTP
        "smtp_responsive": str(report.smtp.responsive) if report.smtp else "",
        "smtp_banner": report.smtp.banner if report.smtp else "",
        "smtp_starttls": str(report.smtp.supports_starttls) if report.smtp else "",
        # Subdomains / Passive
        "subdomains_found": _join(resolved_subs),
        "ct_entries_count": str(ct_count),
        "ct_recent_count": str(ct_recent),
        "passive_dns_hits": str(len(report.passive.passive_dns_hits)) if report.passive else "0",
        # Edge cases
        "is_wildcard": str(report.edge_cases.is_wildcard),
        "is_cdn": str(report.edge_cases.is_cdn),
        "cdn_provider": report.edge_cases.cdn_provider or "",
        "cloud_provider": report.edge_cases.cloud_provider or "",
        "cloud_artifacts": _join(report.edge_cases.cloud_artifacts),
        "has_ipv6": str(report.edge_cases.has_ipv6),
        "ipv6_reachable": str(report.edge_cases.ipv6_reachable),
        "split_horizon_mismatch": str(report.edge_cases.split_horizon_mismatch),
        "dangling_cnames": _join(report.edge_cases.dangling_cnames),
        # Decommission
        "decommission_likely": str(report.decommission.likely_decommissioned),
        "decommission_evidence": _join(report.decommission.evidence),
        # WAF
        "waf_detected": str(report.waf.detected) if report.waf else "",
        "waf_provider": report.waf.provider or "" if report.waf else "",
        "waf_blocking": str(report.waf.is_blocking) if report.waf else "",
        "waf_evidence": _join(report.waf.evidence) if report.waf else "",
        # ASN
        "asn_ip": report.asn.ip if report.asn else "",
        "asn_number": str(report.asn.asn) if report.asn and report.asn.asn else "",
        "asn_org": report.asn.asn_org or "" if report.asn else "",
        "asn_isp": report.asn.isp or "" if report.asn else "",
        "asn_country": report.asn.country or "" if report.asn else "",
        "asn_city": report.asn.city or "" if report.asn else "",
        "asn_is_cloud": str(report.asn.is_cloud) if report.asn else "",
        "asn_cloud_provider": report.asn.cloud_provider or "" if report.asn else "",
        # Metadata
        "scan_started": _dt(report.scan_started),
        "scan_finished": _dt(report.scan_finished),
        "scan_duration_s": f"{report.scan_duration_s:.2f}" if report.scan_duration_s else "",
    }
    return row


def format_csv(reports: DomainReport | list[DomainReport]) -> str:
    """Serialize one or more DomainReports to a CSV string with headers."""
    if isinstance(reports, DomainReport):
        reports = [reports]

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for report in reports:
        writer.writerow(_report_to_csv_row(report))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_VERDICT_COLORS = {
    "active": "#22c55e",
    "inactive": "#ef4444",
    "parked": "#f59e0b",
    "forwarding": "#3b82f6",
    "mail-only": "#8b5cf6",
    "suspended": "#dc2626",
    "for-sale": "#f97316",
    "error": "#6b7280",
    "unknown": "#6b7280",
}


def _html_escape(text: str) -> str:
    """Minimal HTML escaping."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _html_section(title: str, rows: list[tuple[str, str]]) -> str:
    """Build an HTML section with a title and key-value rows."""
    if not rows:
        return ""
    html = f'<div class="section"><h3>{_html_escape(title)}</h3><table>\n'
    for label, value in rows:
        html += f"<tr><td class='label'>{_html_escape(label)}</td>"
        html += f"<td>{_html_escape(str(value))}</td></tr>\n"
    html += "</table></div>\n"
    return html


def _html_list_section(title: str, items: list[str]) -> str:
    """Build an HTML section with a bulleted list."""
    if not items:
        return ""
    html = f'<div class="section"><h3>{_html_escape(title)}</h3><ul>\n'
    for item in items:
        html += f"<li>{_html_escape(item)}</li>\n"
    html += "</ul></div>\n"
    return html


def format_html(reports: DomainReport | list[DomainReport]) -> str:
    """Generate a self-contained HTML report with inline CSS."""
    if isinstance(reports, DomainReport):
        reports = [reports]

    css = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
           'Helvetica Neue', Arial, sans-serif; background: #0f172a; color: #e2e8f0;
           padding: 2rem; line-height: 1.6; }
    h1 { font-size: 1.8rem; margin-bottom: 1.5rem; color: #38bdf8; }
    .report { background: #1e293b; border-radius: 12px; padding: 1.5rem;
              margin-bottom: 2rem; border: 1px solid #334155; }
    .report-header { display: flex; justify-content: space-between;
                     align-items: center; margin-bottom: 1rem;
                     border-bottom: 1px solid #334155; padding-bottom: 1rem; }
    .domain { font-size: 1.4rem; font-weight: 700; color: #f1f5f9; }
    .verdict { font-size: 1.1rem; font-weight: 600; padding: 0.3rem 0.9rem;
               border-radius: 6px; text-transform: uppercase; letter-spacing: 0.05em; }
    .section { margin-top: 1rem; }
    .section h3 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.1em;
                  color: #94a3b8; margin-bottom: 0.5rem;
                  border-bottom: 1px solid #334155; padding-bottom: 0.3rem; }
    table { width: 100%; border-collapse: collapse; }
    td { padding: 0.25rem 0.5rem; vertical-align: top; font-size: 0.9rem; }
    td.label { color: #94a3b8; width: 180px; white-space: nowrap; }
    ul { list-style: disc; padding-left: 1.5rem; }
    li { font-size: 0.9rem; margin-bottom: 0.2rem; }
    .reasoning { background: #0f172a; border-radius: 6px; padding: 1rem;
                 margin-top: 1rem; white-space: pre-wrap; font-size: 0.9rem;
                 border: 1px solid #334155; }
    .meta { font-size: 0.8rem; color: #64748b; margin-top: 1rem; }
    """

    parts: list[str] = []
    parts.append("<!DOCTYPE html>\n<html lang='en'>\n<head>")
    parts.append("<meta charset='UTF-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append(f"<title>hostprobe report</title>\n<style>{css}</style>\n</head>\n<body>")
    parts.append(f"<h1>hostprobe report &mdash; {len(reports)} domain(s)</h1>")

    for r in reports:
        vc = _VERDICT_COLORS.get(r.verdict.value, "#6b7280")
        parts.append('<div class="report">')
        parts.append('<div class="report-header">')
        parts.append(f'<span class="domain">{_html_escape(r.domain)}</span>')
        parts.append(
            f'<span class="verdict" style="background:{vc};color:#fff">'
            f"{_html_escape(r.verdict.value)}</span>"
        )
        parts.append("</div>")

        # DNS
        dns = r.dns
        dns_rows = [
            ("Classification", dns.classification.value),
            ("DNSSEC", dns.dnssec_status),
        ]
        if dns.cname_chain:
            dns_rows.append(("CNAME Chain", " → ".join(dns.cname_chain)))
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "SRV"):
            vals = dns.records.get(rtype, [])
            if vals:
                dns_rows.append((rtype, ", ".join(vals)))
        parts.append(_html_section("DNS", dns_rows))

        # WHOIS
        w = r.whois
        whois_rows = [
            ("Registered", str(w.registered)),
            ("Registrar", w.registrar or "—"),
        ]
        if w.creation_date:
            whois_rows.append(("Created", str(w.creation_date)))
        if w.expiry_date:
            whois_rows.append(("Expires", str(w.expiry_date)))
        if w.nameservers:
            whois_rows.append(("Name Servers", ", ".join(w.nameservers)))
        if w.recently_expired:
            whois_rows.append(("Recently Expired", "Yes"))
        parts.append(_html_section("WHOIS", whois_rows))

        # Subdomains
        if r.subdomains:
            sub_items = [
                f"{s.fqdn} → {', '.join(s.addresses)}" if s.resolved else f"{s.fqdn} (unresolved)"
                for s in r.subdomains[:30]
            ]
            parts.append(_html_list_section("Subdomains", sub_items))

        # Passive
        if r.passive:
            passive_rows: list[tuple[str, str]] = []
            if r.passive.ct_entries:
                ct_names = [e.common_name for e in r.passive.ct_entries[:10]]
                passive_rows.append(("CT Logs", ", ".join(ct_names)))
            if r.passive.discovered_subdomains:
                passive_rows.append(("Discovered Subs", ", ".join(sorted(r.passive.discovered_subdomains)[:10])))
            if passive_rows:
                parts.append(_html_section("Passive Recon", passive_rows))

        # Ports
        if r.port_probes:
            port_items = []
            for pp in r.port_probes:
                port_items.append(f":{pp.port} — {pp.state.value} ({pp.method})")
            parts.append(_html_list_section("Port Probes", port_items))

        # TLS
        if r.tls:
            tls_rows = [
                ("Handshake", "OK" if r.tls.handshake_ok else f"FAIL: {r.tls.error_reason or '?'}"),
                ("Subject CN", r.tls.cert_cn or "—"),
                ("Issuer", r.tls.issuer or "—"),
                ("SANs", ", ".join(r.tls.cert_san_list) if r.tls.cert_san_list else "—"),
                ("Protocol", r.tls.tls_version or "—"),
                ("Expired", str(r.tls.is_expired)),
                ("Matches Domain", str(r.tls.cert_matches_domain)),
            ]
            if r.tls.not_after:
                tls_rows.append(("Not After", str(r.tls.not_after)))
            parts.append(_html_section("TLS Certificate", tls_rows))

        # HTTP
        if r.http:
            http_rows = [
                ("Status", str(r.http.status_code or "—")),
                ("Server", r.http.server_header or "—"),
            ]
            if r.http.redirect_target:
                http_rows.append(("Redirect", r.http.redirect_target))
            parts.append(_html_section("HTTP", http_rows))

        # WAF
        if r.waf and r.waf.detected:
            waf_rows = [
                ("Provider", r.waf.provider or "?"),
                ("Blocking", "Yes" if r.waf.is_blocking else "No"),
            ]
            parts.append(_html_section("WAF / Firewall", waf_rows))
            if r.waf.evidence:
                parts.append(_html_list_section("WAF Evidence", r.waf.evidence[:5]))

        # ASN
        if r.asn and r.asn.asn:
            asn_rows = [
                ("IP", r.asn.ip),
                ("ASN", f"AS{r.asn.asn}"),
                ("Organization", r.asn.asn_org or "—"),
            ]
            if r.asn.isp:
                asn_rows.append(("ISP", r.asn.isp))
            loc = ", ".join(p for p in [r.asn.city, r.asn.country] if p)
            if loc:
                asn_rows.append(("Location", loc))
            if r.asn.is_cloud:
                asn_rows.append(("Cloud Provider", r.asn.cloud_provider or "?"))
            parts.append(_html_section("ASN / Geolocation", asn_rows))

        # SMTP
        if r.smtp:
            smtp_rows = [
                ("Banner", r.smtp.banner or "—"),
                ("STARTTLS", str(r.smtp.supports_starttls)),
                ("Responsive", str(r.smtp.responsive)),
            ]
            parts.append(_html_section("SMTP", smtp_rows))

        # Banners
        if r.banners:
            banner_items = [f":{b.port} — {b.banner_text[:120]}" for b in r.banners if b.banner_text]
            if banner_items:
                parts.append(_html_list_section("Banners", banner_items))

        # Edge Cases
        edge = r.edge_cases
        edge_items: list[str] = []
        if edge.is_wildcard:
            edge_items.append("Wildcard DNS")
        if edge.is_cdn:
            edge_items.append(f"CDN: {edge.cdn_provider}")
        if edge.cloud_provider:
            edge_items.append(f"Cloud: {edge.cloud_provider}")
        if edge.has_ipv6:
            edge_items.append(f"IPv6: {'reachable' if edge.ipv6_reachable else 'AAAA only'}")
        if edge.dangling_cnames:
            edge_items.append(f"{len(edge.dangling_cnames)} dangling CNAME(s)")
        if edge_items:
            parts.append(_html_list_section("Edge Cases", edge_items))

        # Decommission
        if r.decommission.likely_decommissioned:
            parts.append(
                _html_list_section("Decommission Signals", r.decommission.evidence)
            )

        # Reasoning
        if r.reasoning:
            parts.append(
                f'<div class="reasoning">{_html_escape(chr(10).join(r.reasoning))}</div>'
            )

        # Meta
        dur = f"{r.scan_duration_s:.1f}s" if r.scan_duration_s else "?"
        parts.append(f'<div class="meta">Scanned {r.scan_started or "?"} — {dur}</div>')
        parts.append("</div>")  # close .report

    parts.append("</body>\n</html>")
    return "\n".join(parts)
