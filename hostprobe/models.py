"""Data models for hostprobe results."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DNSClassification(enum.Enum):
    """Classification of the DNS response for a domain."""
    RESOLVED = "resolved"
    NXDOMAIN = "nxdomain"
    SERVFAIL = "servfail"
    NOERROR_NODATA = "noerror_nodata"


class PortState(enum.Enum):
    """State of a TCP port probe."""
    OPEN = "open"
    CLOSED = "closed"       # RST received — proof of life
    FILTERED = "filtered"   # Timeout — firewall or dead
    ERROR = "error"


class Verdict(enum.Enum):
    """Final verdict for a domain."""
    ALIVE = "alive"
    LIKELY_DEAD = "likely_dead"
    FILTERED = "filtered"
    PARTIAL = "partial"                           # e.g. MX-only, TXT-only
    INVESTIGATE = "investigate"                    # e.g. SERVFAIL, DNSSEC issue
    RECENTLY_DECOMMISSIONED = "recently_decommissioned"

    @property
    def exit_code(self) -> int:
        return _VERDICT_EXIT_CODES[self]


_VERDICT_EXIT_CODES: dict[Verdict, int] = {
    Verdict.ALIVE: 0,
    Verdict.LIKELY_DEAD: 1,
    Verdict.INVESTIGATE: 2,
    Verdict.PARTIAL: 3,
    Verdict.FILTERED: 4,
    Verdict.RECENTLY_DECOMMISSIONED: 5,
}


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

@dataclass
class DNSResult:
    """Result of DNS classification and record enumeration."""
    classification: DNSClassification
    rcode: str
    records: dict[str, list[str]]       # type → values
    resolvers_queried: list[str]
    authoritative: bool
    dnssec_status: str                  # "valid" | "invalid" | "unsigned"
    cname_chain: list[str]              # ordered chain of CNAME hops


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

@dataclass
class WhoisResult:
    """WHOIS registration status."""
    registered: bool
    registrar: str | None
    creation_date: datetime | None
    expiry_date: datetime | None
    nameservers: list[str]
    recently_expired: bool              # expired < 90 days ago


# ---------------------------------------------------------------------------
# Passive Recon
# ---------------------------------------------------------------------------

@dataclass
class CTEntry:
    """A single Certificate Transparency log entry."""
    common_name: str
    issuer: str
    not_before: datetime | None
    not_after: datetime | None
    is_recent: bool                     # issued < 90 days ago


@dataclass
class PassiveResult:
    """Aggregated passive recon data."""
    ct_entries: list[CTEntry] = field(default_factory=list)
    passive_dns_hits: list[dict] = field(default_factory=list)
    discovered_subdomains: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Host Discovery
# ---------------------------------------------------------------------------

@dataclass
class ICMPResult:
    """ICMP ping result."""
    reachable: bool
    latency_ms: float | None = None


@dataclass
class PortProbe:
    """Result of a TCP port probe."""
    port: int
    state: PortState
    latency_ms: float | None = None
    method: str = "connect"             # "connect" or "syn"


@dataclass
class TLSResult:
    """TLS handshake and certificate details."""
    handshake_ok: bool
    cert_cn: str | None = None
    cert_san_list: list[str] = field(default_factory=list)
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    is_expired: bool = False
    expires_soon: bool = False          # < 30 days
    tls_version: str | None = None
    cert_matches_domain: bool = False
    error_reason: str | None = None     # why handshake failed


@dataclass
class SMTPResult:
    """SMTP validation result."""
    banner: str = ""
    ehlo_response: str = ""
    supports_starttls: bool = False
    responsive: bool = False


@dataclass
class HTTPResult:
    """HTTP probe result."""
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    redirect_target: str | None = None
    server_header: str | None = None


@dataclass
class BannerResult:
    """Raw banner grab result."""
    port: int
    banner_text: str = ""
    protocol_guess: str | None = None   # SSH, SMTP, FTP, etc.


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

@dataclass
class EdgeCaseFlags:
    """Flags for various edge / niche cases."""
    is_wildcard: bool = False
    is_cdn: bool = False
    cdn_provider: str | None = None
    cloud_provider: str | None = None
    cloud_artifacts: list[str] = field(default_factory=list)
    has_ipv6: bool = False
    ipv6_reachable: bool = False
    split_horizon_mismatch: bool = False
    dangling_cnames: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# WAF Detection
# ---------------------------------------------------------------------------

@dataclass
class WAFResult:
    """WAF / firewall detection result."""
    detected: bool = False
    provider: str | None = None          # e.g. "Cloudflare", "AWS WAF"
    evidence: list[str] = field(default_factory=list)
    is_blocking: bool = False            # True if WAF returned a challenge/block


# ---------------------------------------------------------------------------
# ASN / Geolocation
# ---------------------------------------------------------------------------

@dataclass
class ASNInfo:
    """ASN and IP geolocation data."""
    ip: str = ""
    asn: int | None = None
    asn_org: str | None = None
    isp: str | None = None
    country: str | None = None
    city: str | None = None
    is_cloud: bool = False               # belongs to known cloud provider
    cloud_provider: str | None = None


# ---------------------------------------------------------------------------
# Decommission
# ---------------------------------------------------------------------------

@dataclass
class DecommissionSignals:
    """Signals indicating recent decommission."""
    passive_dns_last_seen: datetime | None = None
    cert_still_valid: bool = False
    last_known_ip: str | None = None
    likely_decommissioned: bool = False
    evidence: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Subdomain
# ---------------------------------------------------------------------------

@dataclass
class SubdomainEntry:
    """Result for a single subdomain."""
    fqdn: str
    resolved: bool
    addresses: list[str] = field(default_factory=list)
    cname_target: str | None = None


# ---------------------------------------------------------------------------
# Aggregate Report
# ---------------------------------------------------------------------------

@dataclass
class DomainReport:
    """Complete assessment report for a single domain."""
    domain: str
    verdict: Verdict
    reasoning: list[str] = field(default_factory=list)

    # Components
    dns: DNSResult | None = None
    whois: WhoisResult | None = None
    subdomains: list[SubdomainEntry] = field(default_factory=list)
    passive: PassiveResult | None = None
    icmp: ICMPResult | None = None
    port_probes: list[PortProbe] = field(default_factory=list)
    tls: TLSResult | None = None
    smtp: SMTPResult | None = None
    http: HTTPResult | None = None
    banners: list[BannerResult] = field(default_factory=list)
    edge_cases: EdgeCaseFlags = field(default_factory=EdgeCaseFlags)
    decommission: DecommissionSignals = field(default_factory=DecommissionSignals)
    waf: WAFResult | None = None
    asn: ASNInfo | None = None

    # Metadata
    scan_started: datetime | None = None
    scan_finished: datetime | None = None
    scan_duration_s: float | None = None
