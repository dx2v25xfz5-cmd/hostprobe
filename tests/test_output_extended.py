"""Tests for output formatting: HTML, WAF/ASN terminal + CSV columns."""

from __future__ import annotations

from hostprobe.models import (
    ASNInfo,
    DNSClassification,
    DNSResult,
    DecommissionSignals,
    DomainReport,
    EdgeCaseFlags,
    HTTPResult,
    Verdict,
    WAFResult,
    WhoisResult,
)
from hostprobe.output import format_csv, format_html, format_terminal


def _make_report(**overrides) -> DomainReport:
    """Build a minimal DomainReport with sensible defaults."""
    defaults = dict(
        domain="example.com",
        verdict=Verdict.ALIVE,
        reasoning=["Test reasoning"],
        dns=DNSResult(
            classification=DNSClassification.RESOLVED,
            rcode="NOERROR",
            records={"A": ["93.184.216.34"]},
            resolvers_queried=["system"],
            authoritative=False,
            dnssec_status="unsigned",
            cname_chain=[],
        ),
        whois=WhoisResult(
            registered=True,
            registrar="Example Registrar",
            creation_date=None,
            expiry_date=None,
            nameservers=["ns1.example.com"],
            recently_expired=False,
        ),
        subdomains=[],
        passive=None,
        icmp=None,
        port_probes=[],
        tls=None,
        smtp=None,
        http=None,
        banners=[],
        edge_cases=EdgeCaseFlags(),
        decommission=DecommissionSignals(),
        waf=None,
        asn=None,
        scan_started=None,
        scan_finished=None,
        scan_duration_s=5.0,
    )
    defaults.update(overrides)
    return DomainReport(**defaults)


class TestWAFTerminalOutput:
    """Tests for WAF section in terminal output."""

    def test_waf_section_appears_when_detected(self):
        report = _make_report(
            waf=WAFResult(
                detected=True, provider="Cloudflare",
                evidence=["cf-ray header"], is_blocking=True,
            )
        )
        output = format_terminal(report, use_color=False)
        assert "WAF / FIREWALL" in output
        assert "Cloudflare" in output
        assert "BLOCKING" in output

    def test_waf_section_absent_when_not_detected(self):
        report = _make_report(
            waf=WAFResult(detected=False, provider=None, evidence=[], is_blocking=False)
        )
        output = format_terminal(report, use_color=False)
        assert "WAF / FIREWALL" not in output

    def test_waf_none_no_section(self):
        report = _make_report(waf=None)
        output = format_terminal(report, use_color=False)
        assert "WAF / FIREWALL" not in output


class TestASNTerminalOutput:
    """Tests for ASN section in terminal output."""

    def test_asn_section_appears(self):
        report = _make_report(
            asn=ASNInfo(
                ip="93.184.216.34", asn=15133, asn_org="Edgecast",
                isp="Edgecast Inc.", country="US", city="LA",
                is_cloud=True, cloud_provider="Verizon Digital Media",
            )
        )
        output = format_terminal(report, use_color=False)
        assert "ASN / GEO" in output
        assert "AS15133" in output
        assert "Edgecast" in output

    def test_asn_none_no_section(self):
        report = _make_report(asn=None)
        output = format_terminal(report, use_color=False)
        assert "ASN / GEO" not in output


class TestCSVWAFASNColumns:
    """Tests for WAF/ASN columns in CSV output."""

    def test_csv_has_waf_columns(self):
        report = _make_report(
            waf=WAFResult(
                detected=True, provider="Cloudflare",
                evidence=["cf-ray"], is_blocking=False,
            )
        )
        csv_text = format_csv(report)
        assert "waf_detected" in csv_text
        assert "waf_provider" in csv_text
        assert "Cloudflare" in csv_text

    def test_csv_has_asn_columns(self):
        report = _make_report(
            asn=ASNInfo(
                ip="1.2.3.4", asn=12345, asn_org="TestOrg",
                isp=None, country="DE", city="Berlin",
                is_cloud=False, cloud_provider=None,
            )
        )
        csv_text = format_csv(report)
        assert "asn_number" in csv_text
        assert "12345" in csv_text
        assert "TestOrg" in csv_text


class TestHTMLReport:
    """Tests for format_html()."""

    def test_basic_structure(self):
        report = _make_report()
        html = format_html(report)
        assert "<!DOCTYPE html>" in html
        assert "example.com" in html
        assert "hostprobe report" in html
        assert "</html>" in html

    def test_contains_waf_section(self):
        report = _make_report(
            waf=WAFResult(
                detected=True, provider="AWS WAF",
                evidence=["x-amzn-waf"], is_blocking=True,
            )
        )
        html = format_html(report)
        assert "WAF / Firewall" in html
        assert "AWS WAF" in html

    def test_contains_asn_section(self):
        report = _make_report(
            asn=ASNInfo(
                ip="1.2.3.4", asn=99999, asn_org="BigISP",
                isp="BigISP Inc", country="FR", city="Paris",
                is_cloud=False, cloud_provider=None,
            )
        )
        html = format_html(report)
        assert "ASN / Geolocation" in html
        assert "AS99999" in html
        assert "BigISP" in html

    def test_multiple_reports(self):
        r1 = _make_report(domain="a.com")
        r2 = _make_report(domain="b.com")
        html = format_html([r1, r2])
        assert "2 domain(s)" in html
        assert "a.com" in html
        assert "b.com" in html

    def test_html_escapes_domain(self):
        report = _make_report(domain="<script>alert(1)</script>.com")
        html = format_html(report)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
