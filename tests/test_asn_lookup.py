"""Tests for ASN lookup module."""

from __future__ import annotations

import pytest
from unittest.mock import patch, AsyncMock

from hostprobe.asn_lookup import lookup_asn, lookup_multiple_asns
from hostprobe.models import ASNInfo


class TestLookupASN:
    """Tests for lookup_asn()."""

    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        expected = ASNInfo(
            ip="93.184.216.34", asn=15133, asn_org="Edgecast",
            isp="Edgecast Inc.", country="United States", city="Los Angeles",
            is_cloud=False, cloud_provider=None,
        )
        with patch("hostprobe.asn_lookup._query_ip_api", new_callable=AsyncMock, return_value=expected):
            result = await lookup_asn("93.184.216.34")
        assert isinstance(result, ASNInfo)
        assert result.ip == "93.184.216.34"
        assert result.asn == 15133
        assert result.country == "United States"

    @pytest.mark.asyncio
    async def test_failed_lookup_returns_minimal_info(self):
        ip_fail = ASNInfo(ip="1.2.3.4")
        cymru_fail = ASNInfo(ip="1.2.3.4")
        with patch("hostprobe.asn_lookup._query_ip_api", new_callable=AsyncMock, return_value=ip_fail):
            with patch("hostprobe.asn_lookup._query_cymru", new_callable=AsyncMock, return_value=cymru_fail):
                result = await lookup_asn("1.2.3.4")
        assert isinstance(result, ASNInfo)
        assert result.ip == "1.2.3.4"
        assert result.asn is None

    @pytest.mark.asyncio
    async def test_cloud_detection(self):
        expected = ASNInfo(
            ip="52.0.0.1", asn=16509, asn_org="AMAZON-02",
            isp="Amazon.com", country="US", city="Seattle",
            is_cloud=True, cloud_provider="AWS",
        )
        with patch("hostprobe.asn_lookup._query_ip_api", new_callable=AsyncMock, return_value=expected):
            result = await lookup_asn("52.0.0.1")
        assert result.is_cloud is True
        assert result.cloud_provider == "AWS"


class TestLookupMultipleASNs:
    """Tests for lookup_multiple_asns()."""

    @pytest.mark.asyncio
    async def test_returns_results_for_each_ip(self):
        async def mock_lookup(ip, timeout=5.0):
            return ASNInfo(ip=ip, asn=12345, asn_org="Test")

        with patch("hostprobe.asn_lookup.lookup_asn", side_effect=mock_lookup):
            results = await lookup_multiple_asns(["1.2.3.4", "5.6.7.8"])
        assert len(results) == 2
