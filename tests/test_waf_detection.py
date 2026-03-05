"""Tests for WAF detection module."""

from __future__ import annotations

from hostprobe.models import HTTPResult
from hostprobe.waf_detection import detect_waf


class TestDetectWAF:
    """Tests for detect_waf()."""

    def test_no_waf_plain_server(self):
        http = HTTPResult(
            status_code=200,
            server_header="nginx/1.24",
            headers={"Server": "nginx/1.24"},
        )
        result = detect_waf(http)
        assert result.detected is False
        assert result.provider is None

    def test_cloudflare_detected(self):
        http = HTTPResult(
            status_code=403,
            server_header="cloudflare",
            headers={"Server": "cloudflare", "CF-RAY": "abc123"},
        )
        result = detect_waf(http)
        assert result.detected is True
        assert result.provider == "Cloudflare"

    def test_aws_waf_detected(self):
        http = HTTPResult(
            status_code=403,
            server_header="awselb/2.0",
            headers={"x-amzn-waf-action": "block"},
        )
        result = detect_waf(http)
        assert result.detected is True
        assert result.provider == "AWS WAF"

    def test_blocking_status(self):
        http = HTTPResult(
            status_code=403,
            server_header="cloudflare",
            headers={"Server": "cloudflare"},
        )
        result = detect_waf(http)
        assert result.detected is True
        assert result.is_blocking is True

    def test_none_input_returns_no_waf(self):
        result = detect_waf(None)
        assert result.detected is False

    def test_akamai_detected(self):
        http = HTTPResult(
            status_code=200,
            server_header="AkamaiGHost",
            headers={"Server": "AkamaiGHost"},
        )
        result = detect_waf(http)
        assert result.detected is True
        assert result.provider == "Akamai"
