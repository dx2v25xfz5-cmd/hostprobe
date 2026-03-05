"""Tests for dns_checks module."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hostprobe.dns_checks import (
    check_all_records,
    check_dnssec,
    classify_dns,
    interpret_records,
    trace_cname_chain,
)
from hostprobe.models import DNSClassification


# ---------------------------------------------------------------------------
# classify_dns
# ---------------------------------------------------------------------------

class TestClassifyDNS:
    @pytest.mark.asyncio
    async def test_resolved_domain(self):
        """When resolver returns an A record, classification should be RESOLVED."""
        mock_answer = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = "93.184.216.34"
        mock_answer.__iter__ = lambda self: iter([mock_rdata])

        with patch("hostprobe.dns_checks.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=mock_answer)

            result = await classify_dns("example.com", resolvers=["1.1.1.1"])

        assert result.classification == DNSClassification.RESOLVED
        assert "93.184.216.34" in result.records["A"]

    @pytest.mark.asyncio
    async def test_nxdomain(self):
        """NXDOMAIN from all resolvers → classification NXDOMAIN."""
        import dns.resolver

        with patch("hostprobe.dns_checks.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

            result = await classify_dns("nonexistent12345.com", resolvers=["1.1.1.1"])

        assert result.classification == DNSClassification.NXDOMAIN
        assert result.rcode == "NXDOMAIN"

    @pytest.mark.asyncio
    async def test_noanswer(self):
        """NoAnswer → NOERROR_NODATA classification."""
        import dns.resolver

        with patch("hostprobe.dns_checks.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())

            result = await classify_dns("example.com", resolvers=["1.1.1.1"])

        assert result.classification == DNSClassification.NOERROR_NODATA

    @pytest.mark.asyncio
    async def test_timeout_servfail(self):
        """Timeout from all resolvers → SERVFAIL classification."""
        import dns.exception

        with patch("hostprobe.dns_checks.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=dns.exception.Timeout())

            result = await classify_dns("example.com", resolvers=["1.1.1.1"])

        assert result.classification == DNSClassification.SERVFAIL


# ---------------------------------------------------------------------------
# check_all_records
# ---------------------------------------------------------------------------

class TestCheckAllRecords:
    @pytest.mark.asyncio
    async def test_returns_all_types(self):
        """Should query all record types and return a dict."""
        import dns.resolver

        mock_answer = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = "test-value"
        mock_answer.__iter__ = lambda self: iter([mock_rdata])

        with patch("hostprobe.dns_checks.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            # Return empty for everything except A
            async def _resolve(domain, rdtype):
                if rdtype == "A":
                    return mock_answer
                raise dns.resolver.NoAnswer()

            instance.resolve = AsyncMock(side_effect=_resolve)

            records = await check_all_records("example.com")

        assert "A" in records
        assert "AAAA" in records
        assert "MX" in records
        assert records["A"] == ["test-value"]
        assert records["AAAA"] == []


# ---------------------------------------------------------------------------
# interpret_records
# ---------------------------------------------------------------------------

class TestInterpretRecords:
    def test_mx_interpretation(self):
        records = {"A": [], "AAAA": [], "MX": ["10 mail.example.com."],
                   "TXT": [], "NS": [], "SOA": [], "CAA": [], "SRV": [], "CNAME": []}
        interps = interpret_records(records)
        assert any("mail infrastructure" in i.lower() for i in interps)

    def test_txt_only_interpretation(self):
        records = {"A": [], "AAAA": [], "MX": [],
                   "TXT": ["v=spf1 include:example.com ~all"],
                   "NS": [], "SOA": [], "CAA": [], "SRV": [], "CNAME": []}
        interps = interpret_records(records)
        assert any("verification" in i.lower() for i in interps)

    def test_ns_soa_interpretation(self):
        records = {"A": [], "AAAA": [], "MX": [], "TXT": [],
                   "NS": ["ns1.example.com."], "SOA": ["ns1.example.com. admin.example.com. 2024 ..."],
                   "CAA": [], "SRV": [], "CNAME": []}
        interps = interpret_records(records)
        assert any("zone exists" in i.lower() for i in interps)

    def test_ipv6_only(self):
        records = {"A": [], "AAAA": ["2001:db8::1"], "MX": [], "TXT": [],
                   "NS": [], "SOA": [], "CAA": [], "SRV": [], "CNAME": []}
        interps = interpret_records(records)
        assert any("ipv6" in i.lower() for i in interps)


# ---------------------------------------------------------------------------
# trace_cname_chain
# ---------------------------------------------------------------------------

class TestTraceCnameChain:
    @pytest.mark.asyncio
    async def test_no_cname(self):
        """Domain with no CNAME should return empty chain."""
        import dns.resolver

        with patch("hostprobe.dns_checks.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())

            chain = await trace_cname_chain("example.com")

        assert chain == []

    @pytest.mark.asyncio
    async def test_cname_chain(self):
        """Should follow CNAME hops to terminal A record."""
        import dns.resolver

        call_count = 0

        async def _resolve(domain, rdtype):
            nonlocal call_count
            call_count += 1

            if rdtype == "CNAME" and domain == "www.example.com":
                mock = MagicMock()
                target = MagicMock()
                target.to_text.return_value = "cdn.example.net."
                mock.__getitem__ = lambda self, i: MagicMock(target=target)
                mock.__iter__ = lambda self: iter([MagicMock(target=target)])
                return mock
            elif rdtype == "CNAME":
                raise dns.resolver.NoAnswer()
            elif rdtype == "A":
                mock = MagicMock()
                rdata = MagicMock()
                rdata.to_text.return_value = "1.2.3.4"
                mock.__getitem__ = lambda self, i: rdata
                mock.__iter__ = lambda self: iter([rdata])
                return mock
            raise dns.resolver.NoAnswer()

        with patch("hostprobe.dns_checks.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=_resolve)

            chain = await trace_cname_chain("www.example.com")

        assert "cdn.example.net" in chain
        assert "1.2.3.4" in chain


# ---------------------------------------------------------------------------
# check_dnssec
# ---------------------------------------------------------------------------

class TestCheckDNSSEC:
    @pytest.mark.asyncio
    async def test_unsigned(self):
        """Domain without DNSSEC should return 'unsigned'."""
        import dns.resolver

        mock_answer = MagicMock()
        mock_response = MagicMock()
        mock_response.flags = 0  # no AD flag
        mock_answer.response = mock_response

        with patch("hostprobe.dns_checks.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=mock_answer)
            instance.use_edns = MagicMock()

            status = await check_dnssec("example.com")

        assert status == "unsigned"
