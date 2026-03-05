"""Shared test fixtures and mock factories."""

from __future__ import annotations

import pytest

from hostprobe.models import (
    CTEntry,
    DNSClassification,
    DNSResult,
    DecommissionSignals,
    DomainReport,
    EdgeCaseFlags,
    ICMPResult,
    PassiveResult,
    PortProbe,
    PortState,
    SMTPResult,
    TLSResult,
    HTTPResult,
    Verdict,
    WhoisResult,
)


@pytest.fixture
def resolved_dns() -> DNSResult:
    return DNSResult(
        classification=DNSClassification.RESOLVED,
        rcode="NOERROR",
        records={"A": ["93.184.216.34"], "AAAA": [], "MX": [], "TXT": [],
                 "NS": ["ns1.example.com"], "SOA": ["ns1.example.com"], "CAA": [], "SRV": [], "CNAME": []},
        resolvers_queried=["1.1.1.1", "8.8.8.8"],
        authoritative=True,
        dnssec_status="unsigned",
        cname_chain=[],
    )


@pytest.fixture
def nxdomain_dns() -> DNSResult:
    return DNSResult(
        classification=DNSClassification.NXDOMAIN,
        rcode="NXDOMAIN",
        records={"A": [], "AAAA": [], "MX": [], "TXT": [],
                 "NS": [], "SOA": [], "CAA": [], "SRV": [], "CNAME": []},
        resolvers_queried=["1.1.1.1", "8.8.8.8"],
        authoritative=True,
        dnssec_status="unsigned",
        cname_chain=[],
    )


@pytest.fixture
def alive_whois() -> WhoisResult:
    return WhoisResult(
        registered=True,
        registrar="Example Registrar",
        creation_date=None,
        expiry_date=None,
        nameservers=["ns1.example.com"],
        recently_expired=False,
    )


@pytest.fixture
def dead_whois() -> WhoisResult:
    return WhoisResult(
        registered=False,
        registrar=None,
        creation_date=None,
        expiry_date=None,
        nameservers=[],
        recently_expired=False,
    )
