"""Host discovery: ICMP, TCP probes, TLS handshake, SMTP validation, HTTP, banners."""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
import time
from datetime import datetime, timezone
from typing import Optional

from hostprobe.models import (
    BannerResult,
    HTTPResult,
    ICMPResult,
    PortProbe,
    PortState,
    SMTPResult,
    TLSResult,
)
from hostprobe.utils import run_subprocess

logger = logging.getLogger("hostprobe")

# All exception types that indicate a failed network connection
_CONNECT_ERRORS = (
    asyncio.TimeoutError,
    ConnectionRefusedError,
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    OSError,
    ssl.SSLError,
)


# ---------------------------------------------------------------------------
# ICMP Ping
# ---------------------------------------------------------------------------

async def probe_icmp(host: str, timeout: float = 3.0) -> ICMPResult:
    """Ping the host via subprocess (avoids raw socket / root requirement).

    Uses ``ping -c 1`` on macOS/Linux.
    """
    import platform

    # macOS uses -W in ms (and -t for timeout), Linux uses -W in seconds
    if platform.system() == "Darwin":
        cmd = ["ping", "-c", "1", "-t", str(int(timeout)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]

    rc, stdout, stderr = await run_subprocess(cmd, timeout=timeout + 2)

    if rc == 0:
        # Try per-line format first: "time=12.3 ms" or "time<1ms"
        m = re.search(r"time[=<](\d+\.?\d*)\s*ms", stdout)
        if not m:
            # macOS summary: "round-trip min/avg/max/stddev = 12.3/12.3/12.3/0.0 ms"
            m = re.search(r"round-trip\s+\S+\s*=\s*([\d.]+)/", stdout)
        latency = float(m.group(1)) if m else None
        return ICMPResult(reachable=True, latency_ms=latency)

    return ICMPResult(reachable=False)


# ---------------------------------------------------------------------------
# TCP Port Probes
# ---------------------------------------------------------------------------

async def probe_tcp(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> PortProbe:
    """TCP connect probe on a single port.

    Returns:
        OPEN     — connection succeeded
        CLOSED   — ConnectionRefusedError (RST received = proof of life)
        FILTERED — timeout (firewall or dead)
        ERROR    — other OS-level error
    """
    t0 = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        latency = (time.monotonic() - t0) * 1000
        writer.close()
        await writer.wait_closed()
        return PortProbe(port=port, state=PortState.OPEN, latency_ms=round(latency, 2))
    except ConnectionRefusedError:
        latency = (time.monotonic() - t0) * 1000
        return PortProbe(port=port, state=PortState.CLOSED, latency_ms=round(latency, 2))
    except asyncio.TimeoutError:
        return PortProbe(port=port, state=PortState.FILTERED)
    except OSError as exc:
        logger.debug("TCP probe %s:%d error: %s", host, port, exc)
        return PortProbe(port=port, state=PortState.ERROR)


async def probe_ports(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 5.0,
) -> list[PortProbe]:
    """Probe multiple TCP ports concurrently."""
    ports = ports or [443, 80]
    tasks = [probe_tcp(host, p, timeout) for p in ports]
    return list(await asyncio.gather(*tasks))


# ---------------------------------------------------------------------------
# Nmap SYN Scan (optional)
# ---------------------------------------------------------------------------

async def nmap_syn_scan(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 30.0,
) -> list[PortProbe]:
    """Run ``nmap -sS`` for SYN-level scanning. Requires root + nmap installed."""
    ports = ports or [443, 80]
    port_str = ",".join(str(p) for p in ports)

    rc, stdout, stderr = await run_subprocess(
        ["nmap", "-sS", "-p", port_str, "-oG", "-", "--open", host],
        timeout=timeout,
    )

    if rc != 0:
        if "command not found" in stderr:
            logger.warning("nmap not found — install nmap or drop --nmap flag")
        elif "requires root" in stderr.lower() or "operation not permitted" in stderr.lower():
            logger.warning("nmap SYN scan requires root privileges")
        else:
            logger.warning("nmap failed: %s", stderr.strip())
        return []

    # Parse greppable output
    results: list[PortProbe] = []
    for line in stdout.splitlines():
        if "Ports:" not in line:
            continue
        # e.g. "443/open/tcp//https///, 80/open/tcp//http///"
        ports_part = line.split("Ports:")[1].strip()
        for entry in ports_part.split(","):
            entry = entry.strip()
            parts = entry.split("/")
            if len(parts) >= 2:
                port_num = int(parts[0])
                state_str = parts[1].lower()
                state = {
                    "open": PortState.OPEN,
                    "closed": PortState.CLOSED,
                    "filtered": PortState.FILTERED,
                }.get(state_str, PortState.ERROR)
                results.append(PortProbe(port=port_num, state=state, method="syn"))

    return results


# ---------------------------------------------------------------------------
# TLS Handshake
# ---------------------------------------------------------------------------

async def probe_tls(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    domain: str | None = None,
) -> TLSResult:
    """Perform a TLS handshake and extract certificate details.

    Tries multiple TLS configurations to maximise compatibility:
    1. Default context with verification disabled (accepts self-signed).
    2. Explicit TLS 1.2 fallback (for servers that reject TLS 1.3 ClientHello).

    The *domain* parameter is used for SNI (Server Name Indication) so the
    server presents the correct certificate.
    """
    server_hostname = domain or host

    # Attempt 1 — default (TLS 1.2+ negotiation)
    result = await _try_tls_handshake(host, port, timeout, server_hostname)
    if result.handshake_ok:
        return result

    # Attempt 2 — force TLS 1.2 only (some legacy servers choke on TLS 1.3 CH)
    logger.debug("TLS default handshake failed for %s:%d, retrying with TLS 1.2", host, port)
    result_12 = await _try_tls_handshake(
        host, port, timeout, server_hostname, max_version=ssl.TLSVersion.TLSv1_2,
    )
    if result_12.handshake_ok:
        return result_12

    # Attempt 3 — try without SNI (some broken servers reject SNI entirely)
    if server_hostname != host:
        logger.debug("TLS SNI handshake failed for %s:%d, retrying without SNI", host, port)
        result_nosni = await _try_tls_handshake(host, port, timeout, server_hostname=None)
        if result_nosni.handshake_ok:
            # Still populate domain-match check against original domain
            if domain:
                _check_domain_match(result_nosni, domain)
            return result_nosni

    # All attempts failed — return the first failure result (most informative)
    return result


async def _try_tls_handshake(
    host: str,
    port: int,
    timeout: float,
    server_hostname: str | None,
    *,
    max_version: ssl.TLSVersion | None = None,
) -> TLSResult:
    """Single TLS handshake attempt.  Returns TLSResult (handshake_ok may be False)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if max_version is not None:
        ctx.maximum_version = max_version

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_hostname),
            timeout=timeout,
        )
    except ssl.SSLCertVerificationError as exc:
        # We disabled verification, so this shouldn't fire — but handle it
        logger.debug("TLS cert verification error %s:%d: %s", host, port, exc)
        return TLSResult(handshake_ok=False, error_reason=f"cert verification: {exc}")
    except ssl.SSLError as exc:
        reason = getattr(exc, "reason", str(exc))
        logger.debug("TLS SSL error %s:%d: %s", host, port, reason)
        return TLSResult(handshake_ok=False, error_reason=f"ssl: {reason}")
    except ConnectionResetError:
        logger.debug("TLS connection reset by %s:%d", host, port)
        return TLSResult(handshake_ok=False, error_reason="connection reset")
    except ConnectionRefusedError:
        logger.debug("TLS connection refused by %s:%d", host, port)
        return TLSResult(handshake_ok=False, error_reason="connection refused")
    except asyncio.TimeoutError:
        logger.debug("TLS handshake timed out %s:%d", host, port)
        return TLSResult(handshake_ok=False, error_reason="timeout")
    except OSError as exc:
        logger.debug("TLS OS error %s:%d: %s", host, port, exc)
        return TLSResult(handshake_ok=False, error_reason=f"os: {exc}")

    transport = writer.transport
    ssl_obj = transport.get_extra_info("ssl_object")  # type: ignore[union-attr]

    result = TLSResult(handshake_ok=True)

    if ssl_obj:
        try:
            result.tls_version = ssl_obj.version()
        except Exception:
            pass

        try:
            der_cert = ssl_obj.getpeercert(binary_form=True)
            if der_cert:
                _populate_tls_from_der(result, der_cert, server_hostname or host)
        except Exception as exc:
            logger.debug("Failed to parse TLS cert from %s:%d: %s", host, port, exc)

    _close_writer(writer)
    return result


def _close_writer(writer: asyncio.StreamWriter) -> None:
    """Close a StreamWriter without blocking or raising."""
    try:
        writer.close()
    except Exception:
        pass


def _populate_tls_from_der(result: TLSResult, der_bytes: bytes, domain: str) -> None:
    """Extract CN, SAN, issuer, dates from a DER-encoded certificate.

    Uses ``ssl._ssl._test_decode_cert`` (CPython internal) as primary parser,
    with a fallback regex-based approach for non-CPython or if the internal
    API changes.
    """
    pem = ssl.DER_cert_to_PEM_cert(der_bytes)

    cert_dict = _decode_cert_safe(pem)
    if not cert_dict:
        return

    # Subject — extract CN
    for rdn in cert_dict.get("subject", ()):
        for attr_type, attr_value in rdn:
            if attr_type == "commonName":
                result.cert_cn = attr_value

    # Issuer
    issuer_parts: list[str] = []
    for rdn in cert_dict.get("issuer", ()):
        for attr_type, attr_value in rdn:
            issuer_parts.append(f"{attr_type}={attr_value}")
    if issuer_parts:
        result.issuer = ", ".join(issuer_parts)

    # SAN
    san_list: list[str] = []
    for san_type, san_value in cert_dict.get("subjectAltName", ()):
        if san_type == "DNS":
            san_list.append(san_value)
    result.cert_san_list = san_list

    # Dates
    not_before = cert_dict.get("notBefore")
    not_after = cert_dict.get("notAfter")
    if not_before:
        result.not_before = _parse_ssl_date(not_before)
    if not_after:
        result.not_after = _parse_ssl_date(not_after)
        now = datetime.now(timezone.utc)
        if result.not_after:
            na = result.not_after if result.not_after.tzinfo else result.not_after.replace(tzinfo=timezone.utc)
            result.is_expired = na < now
            from datetime import timedelta
            result.expires_soon = na < now + timedelta(days=30)

    # Does cert match the domain?
    check_domain = domain.lower()
    all_names = san_list + ([result.cert_cn] if result.cert_cn else [])
    for name in all_names:
        name_lower = name.lower()
        if name_lower == check_domain:
            result.cert_matches_domain = True
            break
        # Wildcard match: *.example.com matches sub.example.com
        if name_lower.startswith("*."):
            wildcard_base = name_lower[2:]
            if check_domain.endswith(wildcard_base) and check_domain.count(".") == wildcard_base.count(".") + 1:
                result.cert_matches_domain = True
                break


def _parse_ssl_date(s: str) -> datetime | None:
    """Parse dates from ssl cert dict, e.g. 'Jan  5 00:00:00 2025 GMT'."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _decode_cert_safe(pem: str) -> dict:
    """Decode a PEM certificate to a dict using CPython internals.

    Falls back gracefully if the private API is unavailable.
    """
    import tempfile
    import os

    fd = None
    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        os.write(fd, pem.encode())
        os.close(fd)
        fd = None  # closed
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except (AttributeError, OSError, Exception) as exc:
        logger.debug("_test_decode_cert failed: %s", exc)
        return {}
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                pass


def _check_domain_match(result: TLSResult, domain: str) -> None:
    """Update cert_matches_domain on an existing TLSResult."""
    check_domain = domain.lower()
    all_names = list(result.cert_san_list) + ([result.cert_cn] if result.cert_cn else [])
    for name in all_names:
        name_lower = name.lower()
        if name_lower == check_domain:
            result.cert_matches_domain = True
            return
        if name_lower.startswith("*."):
            wildcard_base = name_lower[2:]
            if check_domain.endswith(wildcard_base) and check_domain.count(".") == wildcard_base.count(".") + 1:
                result.cert_matches_domain = True
                return


# ---------------------------------------------------------------------------
# SMTP Validation
# ---------------------------------------------------------------------------

async def probe_smtp(
    host: str,
    port: int = 25,
    timeout: float = 10.0,
) -> SMTPResult:
    """Connect to an SMTP server, read banner, send EHLO, check STARTTLS.

    Handles connection resets, partial reads, and slow servers gracefully.
    """
    result = SMTPResult()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except _CONNECT_ERRORS as exc:
        logger.debug("SMTP connect to %s:%d failed: %s", host, port, exc)
        return result

    try:
        # Read banner (some servers are slow — give extra time)
        banner_data = await asyncio.wait_for(reader.readline(), timeout=timeout)
        result.banner = banner_data.decode(errors="replace").strip()
        result.responsive = result.banner.startswith("220")

        if result.responsive:
            # Send EHLO
            writer.write(b"EHLO hostprobe.local\r\n")
            await writer.drain()

            # Read multi-line EHLO response
            ehlo_lines: list[str] = []
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                    if not line:
                        break  # EOF
                    text = line.decode(errors="replace").strip()
                    ehlo_lines.append(text)
                    # SMTP multi-line: "250-..." continues, "250 ..." ends
                    if text[:4].endswith(" ") or not text:
                        break
                except asyncio.TimeoutError:
                    break

            result.ehlo_response = "\n".join(ehlo_lines)
            result.supports_starttls = any(
                "STARTTLS" in line.upper() for line in ehlo_lines
            )

            # Graceful quit
            try:
                writer.write(b"QUIT\r\n")
                await writer.drain()
            except _CONNECT_ERRORS:
                pass  # server may have already closed

    except _CONNECT_ERRORS as exc:
        logger.debug("SMTP session error with %s:%d: %s", host, port, exc)
    finally:
        _close_writer(writer)

    return result


# ---------------------------------------------------------------------------
# HTTP Probe
# ---------------------------------------------------------------------------

async def probe_http(
    host: str,
    port: int = 443,
    use_tls: bool = True,
    timeout: float = 5.0,
    domain: str | None = None,
) -> HTTPResult:
    """Make an HTTP request and inspect the response.

    Tries HEAD first (fast), then falls back to GET if the server returns
    405 Method Not Allowed.  Uses a custom Host header when *domain* is
    provided so that name-based virtual hosts respond correctly.
    """
    try:
        import aiohttp

        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{host}:{port}/"

        # Disable TLS verification — we handle that in probe_tls
        conn = aiohttp.TCPConnector(ssl=False)
        headers = {}
        if domain and domain != host:
            headers["Host"] = domain

        client_timeout = aiohttp.ClientTimeout(
            total=timeout,
            connect=min(timeout, 5.0),
            sock_read=timeout,
        )

        async with aiohttp.ClientSession(connector=conn) as session:
            # Try HEAD first
            try:
                async with session.head(
                    url,
                    timeout=client_timeout,
                    allow_redirects=False,
                    headers=headers,
                ) as resp:
                    if resp.status == 405:
                        # Server doesn't allow HEAD — try GET
                        raise aiohttp.ClientResponseError(
                            resp.request_info, resp.history,
                            status=405, message="Method Not Allowed",
                        )
                    resp_headers = {k: v for k, v in resp.headers.items()}
                    return HTTPResult(
                        status_code=resp.status,
                        headers=resp_headers,
                        redirect_target=resp_headers.get("Location"),
                        server_header=resp_headers.get("Server"),
                    )
            except aiohttp.ClientResponseError:
                pass  # fall through to GET

            # Fallback to GET
            async with session.get(
                url,
                timeout=client_timeout,
                allow_redirects=False,
                headers=headers,
            ) as resp:
                resp_headers = {k: v for k, v in resp.headers.items()}
                return HTTPResult(
                    status_code=resp.status,
                    headers=resp_headers,
                    redirect_target=resp_headers.get("Location"),
                    server_header=resp_headers.get("Server"),
                )
    except Exception as exc:
        logger.debug("HTTP probe %s:%d failed: %s", host, port, exc)
        return HTTPResult()


# ---------------------------------------------------------------------------
# Banner Grab
# ---------------------------------------------------------------------------

async def grab_banner(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> BannerResult:
    """Connect to *port* and read raw banner bytes.

    Some services require a probe (e.g. HTTP), but most banner-based
    protocols send data immediately on connect.
    """
    result = BannerResult(port=port)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

        # Try reading — most banner protocols send data first
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        except asyncio.TimeoutError:
            # Server didn't send anything — try sending a HTTP probe
            try:
                writer.write(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            except Exception:
                data = b""

        _close_writer(writer)

        if data:
            result.banner_text = data.decode(errors="replace").strip()
            result.protocol_guess = _guess_protocol(result.banner_text)

    except _CONNECT_ERRORS as exc:
        logger.debug("Banner grab %s:%d failed: %s", host, port, exc)

    return result


def _guess_protocol(banner: str) -> str | None:
    """Guess protocol from banner text."""
    b = banner.upper()
    if b.startswith("SSH-"):
        return "SSH"
    if b.startswith("220 ") or b.startswith("220-"):
        # Could be SMTP or FTP
        if "SMTP" in b or "ESMTP" in b or "MAIL" in b:
            return "SMTP"
        if "FTP" in b:
            return "FTP"
        return "SMTP/FTP"
    if b.startswith("HTTP/"):
        return "HTTP"
    if b.startswith("+OK") or b.startswith("-ERR"):
        return "POP3"
    if b.startswith("* OK"):
        return "IMAP"
    return None
