"""Output formatting: JSON serialization and ANSI-colored terminal output."""

from __future__ import annotations

import dataclasses
import json
import sys
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
    """Progress reporter for batch mode."""

    def __init__(self, total: int, use_color: bool = True, quiet: bool = False):
        self.total = total
        self.current = 0
        self.use_color = use_color
        self.quiet = quiet

    def start_domain(self, domain: str) -> TerminalProgress:
        self.current += 1
        if not self.quiet:
            counter = _c(C.BOLD, f"[{self.current}/{self.total}]", self.use_color)
            sys.stderr.write(f"\n{counter} Scanning {domain}\n")
            sys.stderr.flush()
        return TerminalProgress(domain, self.use_color, self.quiet)


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
