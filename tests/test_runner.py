"""Tests for the runner decision tree logic."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hostprobe.config import Config
from hostprobe.models import (
    CTEntry,
    DNSClassification,
    DNSResult,
    DecommissionSignals,
    ICMPResult,
    PassiveResult,
    PortProbe,
    PortState,
    SubdomainEntry,
    TLSResult,
    HTTPResult,
    SMTPResult,
    Verdict,
    WhoisResult,
    EdgeCaseFlags,
)
from hostprobe.runner import analyze_domain


def _dns(cls: DNSClassification, a_records: list[str] | None = None) -> DNSResult:
    records = {"A": a_records or [], "AAAA": [], "MX": [], "TXT": [],
               "NS": [], "SOA": [], "CAA": [], "SRV": [], "CNAME": []}
    return DNSResult(
        classification=cls, rcode="NOERROR" if cls == DNSClassification.RESOLVED else cls.value.upper(),
        records=records, resolvers_queried=["1.1.1.1"],
        authoritative=True, dnssec_status="unsigned", cname_chain=[],
    )


def _whois(registered: bool = True) -> WhoisResult:
    return WhoisResult(
        registered=registered, registrar="Test", creation_date=None,
        expiry_date=None, nameservers=[], recently_expired=False,
    )


class TestRunnerDecisionTree:
    """High-level tests for the decision tree in runner.analyze_domain."""

    @pytest.mark.asyncio
    async def test_alive_domain(self):
        """Domain that resolves + port open → ALIVE."""
        config = Config(skip_passive=True, ports=[443])

        with (
            patch("hostprobe.runner.classify_dns", new_callable=AsyncMock,
                  return_value=_dns(DNSClassification.RESOLVED, ["1.2.3.4"])),
            patch("hostprobe.runner.check_all_records", new_callable=AsyncMock,
                  return_value={"A": ["1.2.3.4"], "AAAA": [], "MX": [], "TXT": [],
                               "NS": ["ns1.test."], "SOA": ["ns1.test."], "CAA": [], "SRV": [], "CNAME": []}),
            patch("hostprobe.runner.check_whois", new_callable=AsyncMock,
                  return_value=_whois(True)),
            patch("hostprobe.runner.trace_cname_chain", new_callable=AsyncMock,
                  return_value=[]),
            patch("hostprobe.runner.check_dnssec", new_callable=AsyncMock,
                  return_value="unsigned"),
            patch("hostprobe.runner.passive_recon", new_callable=AsyncMock,
                  return_value=PassiveResult()),
            patch("hostprobe.runner.probe_icmp", new_callable=AsyncMock,
                  return_value=ICMPResult(reachable=True, latency_ms=10.0)),
            patch("hostprobe.runner.probe_ports", new_callable=AsyncMock,
                  return_value=[PortProbe(port=443, state=PortState.OPEN, latency_ms=15.0)]),
            patch("hostprobe.runner.nmap_syn_scan", new_callable=AsyncMock,
                  return_value=[]),
            patch("hostprobe.runner.probe_tls", new_callable=AsyncMock,
                  return_value=TLSResult(handshake_ok=True, cert_cn="example.com",
                                        cert_matches_domain=True)),
            patch("hostprobe.runner.probe_http", new_callable=AsyncMock,
                  return_value=HTTPResult(status_code=200, server_header="nginx")),
            patch("hostprobe.runner.probe_smtp", new_callable=AsyncMock,
                  return_value=SMTPResult()),
            patch("hostprobe.runner.grab_banner", new_callable=AsyncMock),
            patch("hostprobe.runner.run_edge_case_checks", new_callable=AsyncMock,
                  return_value=EdgeCaseFlags()),
            patch("hostprobe.runner.detect_cloud_artifacts",
                  return_value=(None, [])),
            patch("hostprobe.runner.detect_dangling_cnames",
                  return_value=[]),
        ):
            report = await analyze_domain("example.com", config)

        assert report.verdict == Verdict.ALIVE
        assert report.domain == "example.com"

    @pytest.mark.asyncio
    async def test_likely_dead_domain(self):
        """NXDOMAIN + unregistered + no subs + no CT → LIKELY_DEAD."""
        config = Config(skip_passive=True, ports=[443])

        with (
            patch("hostprobe.runner.classify_dns", new_callable=AsyncMock,
                  return_value=_dns(DNSClassification.NXDOMAIN)),
            patch("hostprobe.runner.check_all_records", new_callable=AsyncMock,
                  return_value={"A": [], "AAAA": [], "MX": [], "TXT": [],
                               "NS": [], "SOA": [], "CAA": [], "SRV": [], "CNAME": []}),
            patch("hostprobe.runner.check_whois", new_callable=AsyncMock,
                  return_value=_whois(False)),
            patch("hostprobe.runner.trace_cname_chain", new_callable=AsyncMock,
                  return_value=[]),
            patch("hostprobe.runner.check_dnssec", new_callable=AsyncMock,
                  return_value="unsigned"),
            patch("hostprobe.runner.detect_wildcard", new_callable=AsyncMock,
                  return_value=False),
            patch("hostprobe.runner.passive_recon", new_callable=AsyncMock,
                  return_value=PassiveResult()),
            patch("hostprobe.runner.check_subdomains", new_callable=AsyncMock,
                  return_value=[]),
        ):
            report = await analyze_domain("nonexistent12345.com", config)

        assert report.verdict == Verdict.LIKELY_DEAD

    @pytest.mark.asyncio
    async def test_servfail_investigate(self):
        """SERVFAIL → INVESTIGATE verdict."""
        config = Config(skip_passive=True, ports=[443])

        with (
            patch("hostprobe.runner.classify_dns", new_callable=AsyncMock,
                  return_value=_dns(DNSClassification.SERVFAIL)),
            patch("hostprobe.runner.check_all_records", new_callable=AsyncMock,
                  return_value={"A": [], "AAAA": [], "MX": [], "TXT": [],
                               "NS": [], "SOA": [], "CAA": [], "SRV": [], "CNAME": []}),
            patch("hostprobe.runner.check_whois", new_callable=AsyncMock,
                  return_value=_whois(True)),
            patch("hostprobe.runner.trace_cname_chain", new_callable=AsyncMock,
                  return_value=[]),
            patch("hostprobe.runner.check_dnssec", new_callable=AsyncMock,
                  return_value="invalid"),
            patch("hostprobe.runner.detect_wildcard", new_callable=AsyncMock,
                  return_value=False),
            patch("hostprobe.runner.passive_recon", new_callable=AsyncMock,
                  return_value=PassiveResult()),
            patch("hostprobe.runner.check_subdomains", new_callable=AsyncMock,
                  return_value=[]),
            patch("hostprobe.runner.run_edge_case_checks", new_callable=AsyncMock,
                  return_value=EdgeCaseFlags()),
            patch("hostprobe.runner.detect_cloud_artifacts",
                  return_value=(None, [])),
            patch("hostprobe.runner.detect_dangling_cnames",
                  return_value=[]),
        ):
            report = await analyze_domain("broken-dnssec.example.com", config)

        assert report.verdict == Verdict.INVESTIGATE
        assert any("DNSSEC" in r for r in report.reasoning)

    @pytest.mark.asyncio
    async def test_partial_mx_only(self):
        """NOERROR_NODATA with MX only + SMTP not responsive → PARTIAL."""
        config = Config(skip_passive=True, ports=[443])

        records = {"A": [], "AAAA": [], "MX": ["10 mail.example.com."], "TXT": [],
                   "NS": ["ns1.example.com."], "SOA": ["ns1.example.com."],
                   "CAA": [], "SRV": [], "CNAME": []}

        dns_result = DNSResult(
            classification=DNSClassification.NOERROR_NODATA,
            rcode="NOERROR", records=records,
            resolvers_queried=["1.1.1.1"], authoritative=True,
            dnssec_status="unsigned", cname_chain=[],
        )

        with (
            patch("hostprobe.runner.classify_dns", new_callable=AsyncMock,
                  return_value=dns_result),
            patch("hostprobe.runner.check_all_records", new_callable=AsyncMock,
                  return_value=records),
            patch("hostprobe.runner.check_whois", new_callable=AsyncMock,
                  return_value=_whois(True)),
            patch("hostprobe.runner.trace_cname_chain", new_callable=AsyncMock,
                  return_value=[]),
            patch("hostprobe.runner.check_dnssec", new_callable=AsyncMock,
                  return_value="unsigned"),
            patch("hostprobe.runner.detect_wildcard", new_callable=AsyncMock,
                  return_value=False),
            patch("hostprobe.runner.passive_recon", new_callable=AsyncMock,
                  return_value=PassiveResult()),
            patch("hostprobe.runner.check_subdomains", new_callable=AsyncMock,
                  return_value=[]),
            patch("hostprobe.runner.probe_smtp", new_callable=AsyncMock,
                  return_value=SMTPResult(responsive=False)),
            patch("hostprobe.runner.run_edge_case_checks", new_callable=AsyncMock,
                  return_value=EdgeCaseFlags()),
            patch("hostprobe.runner.detect_cloud_artifacts",
                  return_value=(None, [])),
            patch("hostprobe.runner.detect_dangling_cnames",
                  return_value=[]),
        ):
            report = await analyze_domain("mx-only.example.com", config)

        assert report.verdict == Verdict.PARTIAL

    @pytest.mark.asyncio
    async def test_rst_is_alive(self):
        """TCP RST (closed port) → ALIVE (proof of life)."""
        config = Config(skip_passive=True, ports=[443, 80])

        with (
            patch("hostprobe.runner.classify_dns", new_callable=AsyncMock,
                  return_value=_dns(DNSClassification.RESOLVED, ["1.2.3.4"])),
            patch("hostprobe.runner.check_all_records", new_callable=AsyncMock,
                  return_value={"A": ["1.2.3.4"], "AAAA": [], "MX": [], "TXT": [],
                               "NS": [], "SOA": [], "CAA": [], "SRV": [], "CNAME": []}),
            patch("hostprobe.runner.check_whois", new_callable=AsyncMock,
                  return_value=_whois(True)),
            patch("hostprobe.runner.trace_cname_chain", new_callable=AsyncMock,
                  return_value=[]),
            patch("hostprobe.runner.check_dnssec", new_callable=AsyncMock,
                  return_value="unsigned"),
            patch("hostprobe.runner.passive_recon", new_callable=AsyncMock,
                  return_value=PassiveResult()),
            patch("hostprobe.runner.probe_icmp", new_callable=AsyncMock,
                  return_value=ICMPResult(reachable=False)),
            patch("hostprobe.runner.probe_ports", new_callable=AsyncMock,
                  return_value=[
                      PortProbe(port=443, state=PortState.CLOSED, latency_ms=5.0),
                      PortProbe(port=80, state=PortState.CLOSED, latency_ms=5.0),
                  ]),
            patch("hostprobe.runner.nmap_syn_scan", new_callable=AsyncMock,
                  return_value=[]),
            patch("hostprobe.runner.probe_tls", new_callable=AsyncMock,
                  return_value=TLSResult(handshake_ok=False)),
            patch("hostprobe.runner.probe_http", new_callable=AsyncMock,
                  return_value=HTTPResult()),
            patch("hostprobe.runner.probe_smtp", new_callable=AsyncMock,
                  return_value=SMTPResult()),
            patch("hostprobe.runner.grab_banner", new_callable=AsyncMock),
            patch("hostprobe.runner.run_edge_case_checks", new_callable=AsyncMock,
                  return_value=EdgeCaseFlags()),
            patch("hostprobe.runner.detect_cloud_artifacts",
                  return_value=(None, [])),
            patch("hostprobe.runner.detect_dangling_cnames",
                  return_value=[]),
        ):
            report = await analyze_domain("example.com", config)

        assert report.verdict == Verdict.ALIVE
        assert any("RST" in r for r in report.reasoning)
