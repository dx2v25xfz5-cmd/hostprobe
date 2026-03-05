"""Tests for decommission correlation logic."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from hostprobe.decommission import check_decommission_signals
from hostprobe.models import (
    CTEntry,
    DNSClassification,
    DNSResult,
    PassiveResult,
    WhoisResult,
)


def _make_dns(classification: DNSClassification) -> DNSResult:
    return DNSResult(
        classification=classification,
        rcode="NXDOMAIN",
        records={"A": [], "AAAA": [], "MX": [], "TXT": [],
                 "NS": [], "SOA": [], "CAA": [], "SRV": [], "CNAME": []},
        resolvers_queried=["1.1.1.1"],
        authoritative=True,
        dnssec_status="unsigned",
        cname_chain=[],
    )


class TestDecommissionSignals:
    @pytest.mark.asyncio
    async def test_no_signals_when_domain_resolves(self):
        """If domain resolves, no decommission signals should be flagged."""
        dns_result = _make_dns(DNSClassification.RESOLVED)
        result = await check_decommission_signals(
            "example.com", dns_result, None, None
        )
        assert result.likely_decommissioned is False
        assert result.evidence == []

    @pytest.mark.asyncio
    async def test_recent_ct_plus_expired_whois(self):
        """Recent CT cert + recently expired WHOIS = likely decommissioned."""
        now = datetime.now(timezone.utc)
        dns_result = _make_dns(DNSClassification.NXDOMAIN)

        passive = PassiveResult(
            ct_entries=[
                CTEntry(
                    common_name="example.com",
                    issuer="Let's Encrypt",
                    not_before=now - timedelta(days=30),
                    not_after=now + timedelta(days=60),
                    is_recent=True,
                )
            ],
        )

        whois = WhoisResult(
            registered=False,
            registrar=None,
            creation_date=None,
            expiry_date=now - timedelta(days=15),
            nameservers=[],
            recently_expired=True,
        )

        result = await check_decommission_signals(
            "example.com", dns_result, passive, whois
        )

        assert result.likely_decommissioned is True
        assert len(result.evidence) >= 2

    @pytest.mark.asyncio
    async def test_no_signals_when_nothing_found(self):
        """NXDOMAIN + no passive data + no WHOIS expiry → not decommissioned."""
        dns_result = _make_dns(DNSClassification.NXDOMAIN)
        passive = PassiveResult()
        whois = WhoisResult(
            registered=False, registrar=None, creation_date=None,
            expiry_date=None, nameservers=[], recently_expired=False,
        )

        result = await check_decommission_signals(
            "example.com", dns_result, passive, whois
        )

        assert result.likely_decommissioned is False
