"""Tests for host_discovery module."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hostprobe.host_discovery import (
    grab_banner,
    probe_icmp,
    probe_smtp,
    probe_tcp,
)
from hostprobe.models import PortState


# ---------------------------------------------------------------------------
# probe_tcp
# ---------------------------------------------------------------------------

class TestProbeTCP:
    @pytest.mark.asyncio
    async def test_open_port(self):
        """Successful connection → OPEN."""
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    return_value=(mock_reader, mock_writer)):
            result = await probe_tcp("example.com", 443, timeout=2.0)

        assert result.state == PortState.OPEN
        assert result.port == 443
        assert result.latency_ms is not None

    @pytest.mark.asyncio
    async def test_closed_port(self):
        """ConnectionRefusedError → CLOSED (RST = proof of life)."""
        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    side_effect=ConnectionRefusedError()):
            result = await probe_tcp("example.com", 22, timeout=2.0)

        assert result.state == PortState.CLOSED
        assert result.port == 22

    @pytest.mark.asyncio
    async def test_filtered_port(self):
        """TimeoutError → FILTERED."""
        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    side_effect=asyncio.TimeoutError()):
            result = await probe_tcp("example.com", 443, timeout=2.0)

        assert result.state == PortState.FILTERED

    @pytest.mark.asyncio
    async def test_error_port(self):
        """Other OSError → ERROR."""
        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    side_effect=OSError("Network unreachable")):
            result = await probe_tcp("example.com", 443, timeout=2.0)

        assert result.state == PortState.ERROR


# ---------------------------------------------------------------------------
# probe_icmp
# ---------------------------------------------------------------------------

class TestProbeICMP:
    @pytest.mark.asyncio
    async def test_reachable(self):
        """Successful ping → reachable with latency."""
        with patch("hostprobe.host_discovery.run_subprocess",
                    new_callable=AsyncMock,
                    return_value=(0, "64 bytes from 1.2.3.4: time=12.3 ms", "")):
            result = await probe_icmp("1.2.3.4")

        assert result.reachable is True
        assert result.latency_ms == 12.3

    @pytest.mark.asyncio
    async def test_unreachable(self):
        """Failed ping → not reachable."""
        with patch("hostprobe.host_discovery.run_subprocess",
                    new_callable=AsyncMock,
                    return_value=(1, "", "Request timeout")):
            result = await probe_icmp("1.2.3.4")

        assert result.reachable is False


# ---------------------------------------------------------------------------
# probe_smtp
# ---------------------------------------------------------------------------

class TestProbeSMTP:
    @pytest.mark.asyncio
    async def test_responsive_smtp(self):
        """SMTP server with 220 banner and EHLO response."""
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        # Banner + EHLO response
        read_calls = [
            b"220 mail.example.com ESMTP\r\n",
            b"250-mail.example.com\r\n",
            b"250-STARTTLS\r\n",
            b"250 OK\r\n",
        ]
        read_iter = iter(read_calls)
        mock_reader.readline = AsyncMock(side_effect=lambda: next(read_iter))

        with patch("hostprobe.host_discovery.asyncio.wait_for") as mock_wait:
            # First call: open_connection
            # Subsequent calls: readline with timeout
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
        assert result.supports_starttls is True

    @pytest.mark.asyncio
    async def test_connection_refused(self):
        """SMTP connection refused → not responsive."""
        with patch("hostprobe.host_discovery.asyncio.wait_for",
                    new_callable=AsyncMock,
                    side_effect=ConnectionRefusedError()):
            result = await probe_smtp("mail.example.com", 25, timeout=2.0)

        assert result.responsive is False


# ---------------------------------------------------------------------------
# grab_banner
# ---------------------------------------------------------------------------

class TestGrabBanner:
    @pytest.mark.asyncio
    async def test_ssh_banner(self):
        """SSH-2.0 banner → protocol guess SSH."""
        mock_reader = MagicMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.9\r\n")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("hostprobe.host_discovery.asyncio.wait_for") as mock_wait:
            call_num = [0]

            async def _wait_for(coro, timeout=None):
                call_num[0] += 1
                if call_num[0] == 1:
                    return (mock_reader, mock_writer)
                return await coro

            mock_wait.side_effect = _wait_for

            result = await grab_banner("example.com", 22)

        assert result.protocol_guess == "SSH"
        assert "SSH-2.0" in result.banner_text
