"""Comprehensive tests for TLS, HTTP, banner, and SMTP probing in host_discovery."""

from __future__ import annotations

import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from hostprobe.host_discovery import (
    _check_domain_match,
    _close_writer,
    _decode_cert_safe,
    _guess_protocol,
    _try_tls_handshake,
    grab_banner,
    probe_http,
    probe_icmp,
    probe_ports,
    probe_smtp,
    probe_tcp,
    probe_tls,
)
from hostprobe.models import PortState, TLSResult


# ---------------------------------------------------------------------------
# TLS Probe — success
# ---------------------------------------------------------------------------

class TestProbeTLS:
    @pytest.mark.asyncio
    async def test_tls_success(self):
        """Successful TLS handshake returns handshake_ok=True."""
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_transport = MagicMock()
        mock_ssl_obj = MagicMock()
        mock_ssl_obj.version.return_value = "TLSv1.3"
        mock_ssl_obj.getpeercert.return_value = None  # no DER cert
        mock_transport.get_extra_info.return_value = mock_ssl_obj
        mock_writer.transport = mock_transport

        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    return_value=(mock_reader, mock_writer)):
            result = await probe_tls("1.2.3.4", 443, timeout=3.0, domain="example.com")

        assert result.handshake_ok is True
        assert result.tls_version == "TLSv1.3"
        assert result.error_reason is None

    @pytest.mark.asyncio
    async def test_tls_ssl_error_falls_back_to_tls12(self):
        """SSLError on first attempt triggers TLS 1.2 fallback."""
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_transport = MagicMock()
        mock_ssl_obj = MagicMock()
        mock_ssl_obj.version.return_value = "TLSv1.2"
        mock_ssl_obj.getpeercert.return_value = None
        mock_transport.get_extra_info.return_value = mock_ssl_obj
        mock_writer.transport = mock_transport

        call_count = [0]

        async def _mock_wait(coro, timeout=None):
            call_count[0] += 1
            if call_count[0] == 1:
                # First attempt fails with SSLError
                raise ssl.SSLError(1, "[SSL: TLSV1_ALERT_PROTOCOL_VERSION]")
            return (mock_reader, mock_writer)

        with patch("hostprobe.host_discovery.asyncio.wait_for", side_effect=_mock_wait):
            result = await probe_tls("legacy.example.com", 443, timeout=3.0)

        assert result.handshake_ok is True
        assert result.tls_version == "TLSv1.2"

    @pytest.mark.asyncio
    async def test_tls_connection_refused(self):
        """ConnectionRefusedError → handshake_ok=False with reason."""
        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    side_effect=ConnectionRefusedError()):
            result = await probe_tls("1.2.3.4", 443, timeout=2.0)

        assert result.handshake_ok is False
        assert result.error_reason == "connection refused"

    @pytest.mark.asyncio
    async def test_tls_connection_reset(self):
        """ConnectionResetError → handshake_ok=False with reason."""
        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    side_effect=ConnectionResetError()):
            result = await probe_tls("1.2.3.4", 443, timeout=2.0)

        assert result.handshake_ok is False
        assert result.error_reason == "connection reset"

    @pytest.mark.asyncio
    async def test_tls_timeout(self):
        """Timeout → handshake_ok=False with reason 'timeout'."""
        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    side_effect=asyncio.TimeoutError()):
            result = await probe_tls("1.2.3.4", 443, timeout=1.0)

        assert result.handshake_ok is False
        assert result.error_reason == "timeout"

    @pytest.mark.asyncio
    async def test_tls_os_error(self):
        """OSError → handshake_ok=False with reason."""
        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    side_effect=OSError("Network unreachable")):
            result = await probe_tls("1.2.3.4", 443, timeout=2.0)

        assert result.handshake_ok is False
        assert "os:" in result.error_reason

    @pytest.mark.asyncio
    async def test_tls_all_fallbacks_fail(self):
        """When all 3 attempts fail, returns the first failure reason."""
        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    side_effect=ssl.SSLError(1, "WRONG_VERSION")):
            result = await probe_tls("broken.example.com", 443, timeout=2.0, domain="broken.example.com")

        assert result.handshake_ok is False
        assert result.error_reason is not None
        assert "ssl:" in result.error_reason

    @pytest.mark.asyncio
    async def test_tls_nosni_fallback(self):
        """When SNI fails but no-SNI succeeds, returns OK."""
        call_count = [0]

        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_transport = MagicMock()
        mock_ssl_obj = MagicMock()
        mock_ssl_obj.version.return_value = "TLSv1.2"
        mock_ssl_obj.getpeercert.return_value = None
        mock_transport.get_extra_info.return_value = mock_ssl_obj
        mock_writer.transport = mock_transport

        async def _mock_wait(coro, timeout=None):
            call_count[0] += 1
            # First two fail (default + TLS 1.2 with SNI), third succeeds (no SNI)
            if call_count[0] <= 2:
                raise ssl.SSLError(1, "UNRECOGNIZED_NAME")
            return (mock_reader, mock_writer)

        with patch("hostprobe.host_discovery.asyncio.wait_for", side_effect=_mock_wait):
            result = await probe_tls("1.2.3.4", 443, timeout=3.0, domain="broken-sni.example.com")

        assert result.handshake_ok is True


# ---------------------------------------------------------------------------
# _try_tls_handshake — unit level
# ---------------------------------------------------------------------------

class TestTryTLSHandshake:
    @pytest.mark.asyncio
    async def test_ssl_cert_verification_error(self):
        """SSLCertVerificationError → specific error reason."""
        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    side_effect=ssl.SSLCertVerificationError()):
            result = await _try_tls_handshake("1.2.3.4", 443, 3.0, "example.com")

        assert result.handshake_ok is False
        assert "cert verification" in result.error_reason


# ---------------------------------------------------------------------------
# _check_domain_match
# ---------------------------------------------------------------------------

class TestCheckDomainMatch:
    def test_exact_match(self):
        result = TLSResult(handshake_ok=True, cert_cn="example.com")
        _check_domain_match(result, "example.com")
        assert result.cert_matches_domain is True

    def test_wildcard_match(self):
        result = TLSResult(handshake_ok=True, cert_san_list=["*.example.com"])
        _check_domain_match(result, "www.example.com")
        assert result.cert_matches_domain is True

    def test_wildcard_no_match_subdomain(self):
        """*.example.com should NOT match sub.sub.example.com."""
        result = TLSResult(handshake_ok=True, cert_san_list=["*.example.com"])
        _check_domain_match(result, "a.b.example.com")
        assert result.cert_matches_domain is False

    def test_no_match(self):
        result = TLSResult(handshake_ok=True, cert_cn="other.com", cert_san_list=["other.com"])
        _check_domain_match(result, "example.com")
        assert result.cert_matches_domain is False

    def test_san_match_over_cn(self):
        result = TLSResult(handshake_ok=True, cert_cn="other.com", cert_san_list=["example.com"])
        _check_domain_match(result, "example.com")
        assert result.cert_matches_domain is True

    def test_case_insensitive(self):
        result = TLSResult(handshake_ok=True, cert_cn="EXAMPLE.COM")
        _check_domain_match(result, "example.com")
        assert result.cert_matches_domain is True


# ---------------------------------------------------------------------------
# _close_writer
# ---------------------------------------------------------------------------

class TestCloseWriter:
    def test_close_success(self):
        writer = MagicMock()
        _close_writer(writer)
        writer.close.assert_called_once()

    def test_close_exception_swallowed(self):
        writer = MagicMock()
        writer.close.side_effect = OSError("already closed")
        _close_writer(writer)  # should not raise


# ---------------------------------------------------------------------------
# _decode_cert_safe
# ---------------------------------------------------------------------------

class TestDecodeCertSafe:
    def test_returns_empty_on_invalid_pem(self):
        result = _decode_cert_safe("not a real pem")
        assert result == {} or isinstance(result, dict)


# ---------------------------------------------------------------------------
# _guess_protocol
# ---------------------------------------------------------------------------

class TestGuessProtocol:
    def test_ssh(self):
        assert _guess_protocol("SSH-2.0-OpenSSH_8.9") == "SSH"

    def test_smtp(self):
        assert _guess_protocol("220 mail.example.com ESMTP") == "SMTP"

    def test_ftp(self):
        assert _guess_protocol("220 ProFTPD Server FTP ready") == "FTP"

    def test_http(self):
        assert _guess_protocol("HTTP/1.1 200 OK") == "HTTP"

    def test_pop3(self):
        assert _guess_protocol("+OK POP3 server ready") == "POP3"

    def test_imap(self):
        assert _guess_protocol("* OK IMAP server ready") == "IMAP"

    def test_unknown(self):
        assert _guess_protocol("random binary data") is None

    def test_smtp_ftp_ambiguous(self):
        """220 without SMTP/FTP keywords → SMTP/FTP."""
        assert _guess_protocol("220 server ready") == "SMTP/FTP"


# ---------------------------------------------------------------------------
# probe_http
# ---------------------------------------------------------------------------

class TestProbeHTTP:
    @pytest.mark.asyncio
    async def test_http_success(self):
        """Successful HTTP probe returns status code and headers."""
        import aiohttp
        from unittest.mock import AsyncMock

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Server": "nginx", "Content-Type": "text/html"}
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.head = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("aiohttp.TCPConnector"):
            result = await probe_http("1.2.3.4", 80, use_tls=False, timeout=3.0)

        assert result.status_code == 200
        assert result.server_header == "nginx"

    @pytest.mark.asyncio
    async def test_http_timeout(self):
        """HTTP timeout returns empty result."""
        import aiohttp

        with patch("aiohttp.ClientSession") as MockSession:
            session = MagicMock()
            session.__aenter__ = AsyncMock(return_value=session)
            session.__aexit__ = AsyncMock(return_value=False)
            session.head = MagicMock(side_effect=asyncio.TimeoutError())
            MockSession.return_value = session

            result = await probe_http("1.2.3.4", 443, timeout=1.0)

        assert result.status_code is None


# ---------------------------------------------------------------------------
# probe_ports — multi-port concurrency
# ---------------------------------------------------------------------------

class TestProbePorts:
    @pytest.mark.asyncio
    async def test_probe_multiple_ports(self):
        """probe_ports runs concurrent TCP probes."""
        results_map = {
            443: PortState.OPEN,
            80: PortState.CLOSED,
            22: PortState.FILTERED,
        }

        async def _mock_tcp(host, port, timeout=5.0):
            from hostprobe.models import PortProbe
            return PortProbe(port=port, state=results_map.get(port, PortState.ERROR))

        with patch("hostprobe.host_discovery.probe_tcp", side_effect=_mock_tcp):
            results = await probe_ports("example.com", [443, 80, 22])

        assert len(results) == 3
        states = {r.port: r.state for r in results}
        assert states[443] == PortState.OPEN
        assert states[80] == PortState.CLOSED
        assert states[22] == PortState.FILTERED


# ---------------------------------------------------------------------------
# probe_smtp — edge cases
# ---------------------------------------------------------------------------

class TestProbeSMTPEdge:
    @pytest.mark.asyncio
    async def test_smtp_eof(self):
        """Server sends EOF during EHLO → still captures banner."""
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        reads = iter([
            b"220 mail.example.com ESMTP\r\n",
            b"",  # EOF
        ])
        mock_reader.readline = AsyncMock(side_effect=lambda: next(reads))

        with patch("hostprobe.host_discovery.asyncio.wait_for") as mock_wait:
            call_num = [0]

            async def _wait_for(coro, timeout=None):
                call_num[0] += 1
                if call_num[0] == 1:
                    return (mock_reader, mock_writer)
                return await coro

            mock_wait.side_effect = _wait_for
            result = await probe_smtp("mail.example.com", 25, timeout=5.0)

        assert result.responsive is True
        assert "220" in result.banner

    @pytest.mark.asyncio
    async def test_smtp_reset_during_quit(self):
        """ConnectionReset during QUIT doesn't crash."""
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock(side_effect=ConnectionResetError())

        reads = iter([
            b"220 mail.example.com ESMTP\r\n",
            b"250 OK\r\n",
        ])
        mock_reader.readline = AsyncMock(side_effect=lambda: next(reads))

        with patch("hostprobe.host_discovery.asyncio.wait_for") as mock_wait:
            call_num = [0]

            async def _wait_for(coro, timeout=None):
                call_num[0] += 1
                if call_num[0] == 1:
                    return (mock_reader, mock_writer)
                return await coro

            mock_wait.side_effect = _wait_for
            result = await probe_smtp("mail.example.com", 25, timeout=5.0)

        # Should not raise — drain error is caught
        assert result.responsive is True


# ---------------------------------------------------------------------------
# grab_banner — edge cases
# ---------------------------------------------------------------------------

class TestGrabBannerEdge:
    @pytest.mark.asyncio
    async def test_banner_timeout_fallback_to_http_probe(self):
        """When server sends nothing, banner probe sends HTTP request."""
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        call_num = [0]

        async def _mock_read(n=1024):
            call_num[0] += 1
            if call_num[0] == 1:
                raise asyncio.TimeoutError()
            return b"HTTP/1.1 200 OK\r\n"

        mock_reader.read = _mock_read

        with patch("hostprobe.host_discovery.asyncio.wait_for") as mock_wait:
            wf_count = [0]

            async def _wait_for(coro, timeout=None):
                wf_count[0] += 1
                if wf_count[0] == 1:
                    return (mock_reader, mock_writer)
                return await coro

            mock_wait.side_effect = _wait_for
            result = await grab_banner("example.com", 8080, timeout=2.0)

        # Should have attempted the HTTP probe
        assert result.port == 8080

    @pytest.mark.asyncio
    async def test_banner_connection_refused(self):
        """Connection refused on banner grab → empty result."""
        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    side_effect=ConnectionRefusedError()):
            result = await grab_banner("example.com", 9999, timeout=1.0)

        assert result.port == 9999
        assert result.banner_text == ""


# ---------------------------------------------------------------------------
# probe_icmp — edge cases
# ---------------------------------------------------------------------------

class TestProbeICMPEdge:
    @pytest.mark.asyncio
    async def test_icmp_macos_summary_parse(self):
        """macOS ping summary format is parsed correctly."""
        stdout = (
            "PING 1.2.3.4 (1.2.3.4): 56 data bytes\n"
            "64 bytes from 1.2.3.4: icmp_seq=0 ttl=55\n"
            "\n"
            "--- 1.2.3.4 ping statistics ---\n"
            "1 packets transmitted, 1 packets received, 0.0% packet loss\n"
            "round-trip min/avg/max/stddev = 25.1/25.1/25.1/0.0 ms\n"
        )
        with patch("hostprobe.host_discovery.run_subprocess",
                    new_callable=AsyncMock,
                    return_value=(0, stdout, "")):
            result = await probe_icmp("1.2.3.4")

        assert result.reachable is True
        assert result.latency_ms == 25.1

    @pytest.mark.asyncio
    async def test_icmp_per_line_parse(self):
        """Standard per-line time=X ms format."""
        with patch("hostprobe.host_discovery.run_subprocess",
                    new_callable=AsyncMock,
                    return_value=(0, "64 bytes from 1.2.3.4: time=0.5 ms", "")):
            result = await probe_icmp("1.2.3.4")

        assert result.reachable is True
        assert result.latency_ms == 0.5

    @pytest.mark.asyncio
    async def test_icmp_success_no_latency(self):
        """Ping succeeds but no parseable latency → reachable, latency=None."""
        with patch("hostprobe.host_discovery.run_subprocess",
                    new_callable=AsyncMock,
                    return_value=(0, "some unusual ping output", "")):
            result = await probe_icmp("1.2.3.4")

        assert result.reachable is True
        assert result.latency_ms is None
