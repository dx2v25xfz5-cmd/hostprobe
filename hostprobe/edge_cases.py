"""Edge & niche cases: wildcard DNS, reverse DNS, CDN detection, split-horizon, IPv6."""

from __future__ import annotations

import asyncio
import logging
import uuid

import dns.asyncresolver
import dns.reversename
import dns.resolver

from hostprobe.models import EdgeCaseFlags, PortProbe, PortState, TLSResult, HTTPResult

logger = logging.getLogger("hostprobe")


# ---------------------------------------------------------------------------
# Wildcard DNS Detection
# ---------------------------------------------------------------------------

async def detect_wildcard(domain: str, timeout: float = 5.0) -> bool:
    """Test for wildcard DNS by querying a random subdomain.

    If ``<random>.domain`` resolves, the zone has a wildcard record.
    """
    random_sub = uuid.uuid4().hex[:12]
    fqdn = f"{random_sub}.{domain}"
    res = dns.asyncresolver.Resolver()
    res.lifetime = timeout

    try:
        await res.resolve(fqdn, "A")
        logger.debug("Wildcard detected: %s resolves", fqdn)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.resolver.LifetimeTimeout):
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# IPv6 Connectivity Test
# ---------------------------------------------------------------------------

async def check_ipv6_connectivity(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
) -> PortProbe | None:
    """Attempt a TCP connect to *host* (an IPv6 address) on *port*.

    Returns None if no AAAA record / not applicable.
    """
    import time

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
        logger.debug("IPv6 connect %s:%d failed: %s", host, port, exc)
        return PortProbe(port=port, state=PortState.ERROR)


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

async def reverse_dns(ip: str, timeout: float = 5.0) -> str | None:
    """Perform reverse DNS lookup on an IP address. Returns PTR value or None."""
    res = dns.asyncresolver.Resolver()
    res.lifetime = timeout

    try:
        rev_name = dns.reversename.from_address(ip)
        answer = await res.resolve(rev_name, "PTR")
        return answer[0].to_text().rstrip(".")
    except Exception as exc:
        logger.debug("Reverse DNS for %s failed: %s", ip, exc)
        return None


# ---------------------------------------------------------------------------
# CDN Detection
# ---------------------------------------------------------------------------

# Known CDN certificate issuer patterns
CDN_CERT_ISSUERS = {
    "cloudflare": "Cloudflare",
    "google trust services": "Google/GCP",
    "amazon": "AWS CloudFront",
    "globalsign": "CloudFlare/CDN",
    "fastly": "Fastly",
    "let's encrypt": None,  # too generic to attribute
    "digicert": None,       # too generic
}

# CDN HTTP header indicators
CDN_HEADERS = {
    "CF-RAY": "Cloudflare",
    "CF-Cache-Status": "Cloudflare",
    "X-Served-By": "Fastly",
    "X-Cache": None,  # generic — check value
    "Via": None,      # generic — check value
    "X-Azure-Ref": "Azure Front Door",
    "X-Amz-Cf-Id": "AWS CloudFront",
    "X-Amz-Cf-Pop": "AWS CloudFront",
    "X-CDN": None,    # some CDNs self-identify
    "Server": None,   # check for "cloudflare", "AkamaiGHost", etc.
}

# CNAME targets indicating CDN
CDN_CNAME_PATTERNS = {
    ".cloudfront.net": "AWS CloudFront",
    ".fastly.net": "Fastly",
    ".akamaiedge.net": "Akamai",
    ".akamai.net": "Akamai",
    ".azurefd.net": "Azure Front Door",
    ".azureedge.net": "Azure CDN",
    ".edgekey.net": "Akamai",
    ".cloudflare.net": "Cloudflare",
    ".cdn.cloudflare.net": "Cloudflare",
    ".incapdns.net": "Imperva/Incapsula",
    ".sucuri.net": "Sucuri",
    ".googleapis.com": "Google Cloud CDN",
}


def detect_cdn(
    tls_result: TLSResult | None,
    http_result: HTTPResult | None,
    cname_chain: list[str] | None = None,
) -> tuple[bool, str | None]:
    """Detect CDN fronting from TLS cert, HTTP headers, and CNAME chain.

    Returns (is_cdn, provider_name).
    """
    provider: str | None = None

    # Check CNAME chain
    if cname_chain:
        for hop in cname_chain:
            hop_lower = hop.lower()
            for pattern, cdn_name in CDN_CNAME_PATTERNS.items():
                if hop_lower.endswith(pattern):
                    return (True, cdn_name)

    # Check TLS cert issuer
    if tls_result and tls_result.issuer:
        issuer_lower = tls_result.issuer.lower()
        for pattern, cdn_name in CDN_CERT_ISSUERS.items():
            if pattern in issuer_lower and cdn_name:
                provider = cdn_name
                break

    # Check HTTP headers
    if http_result and http_result.headers:
        for header, cdn_name in CDN_HEADERS.items():
            if header in http_result.headers:
                if cdn_name:
                    return (True, cdn_name)
                # Check generic headers for CDN indicators
                val = http_result.headers[header].lower()
                if "cloudflare" in val:
                    return (True, "Cloudflare")
                if "akamai" in val:
                    return (True, "Akamai")
                if "fastly" in val:
                    return (True, "Fastly")
                if "varnish" in val:
                    provider = "Varnish/CDN"

        # Check Server header specifically
        server = http_result.server_header
        if server:
            s_lower = server.lower()
            if "cloudflare" in s_lower:
                return (True, "Cloudflare")
            if "akamaighost" in s_lower:
                return (True, "Akamai")

    if provider:
        return (True, provider)

    return (False, None)


# ---------------------------------------------------------------------------
# Split-Horizon DNS
# ---------------------------------------------------------------------------

async def check_split_horizon(
    domain: str,
    internal_resolver: str,
    timeout: float = 5.0,
) -> bool:
    """Compare public vs internal DNS resolution.

    Returns True if results differ (split-horizon detected).
    """
    res_public = dns.asyncresolver.Resolver()
    res_public.nameservers = ["1.1.1.1"]
    res_public.lifetime = timeout

    res_internal = dns.asyncresolver.Resolver()
    res_internal.nameservers = [internal_resolver]
    res_internal.lifetime = timeout

    async def _query(resolver: dns.asyncresolver.Resolver) -> set[str]:
        try:
            answer = await resolver.resolve(domain, "A")
            return {rdata.to_text() for rdata in answer}
        except Exception:
            return set()

    pub, internal = await asyncio.gather(_query(res_public), _query(res_internal))

    mismatch = pub != internal
    if mismatch:
        logger.debug(
            "Split-horizon detected for %s: public=%s internal=%s",
            domain, pub, internal,
        )
    return mismatch


# ---------------------------------------------------------------------------
# Aggregate edge case checks
# ---------------------------------------------------------------------------

async def run_edge_case_checks(
    domain: str,
    dns_records: dict[str, list[str]],
    tls_result: TLSResult | None,
    http_result: HTTPResult | None,
    cname_chain: list[str] | None,
    internal_resolver: str | None = None,
    timeout: float = 5.0,
) -> EdgeCaseFlags:
    """Run all edge-case checks and return aggregated flags."""
    flags = EdgeCaseFlags()

    # Wildcard
    flags.is_wildcard = await detect_wildcard(domain, timeout)

    # IPv6
    aaaa_records = dns_records.get("AAAA", [])
    if aaaa_records:
        flags.has_ipv6 = True
        ipv6_addr = aaaa_records[0]
        probe = await check_ipv6_connectivity(ipv6_addr, 443, timeout)
        if probe and probe.state in (PortState.OPEN, PortState.CLOSED):
            flags.ipv6_reachable = True

    # CDN
    is_cdn, cdn_name = detect_cdn(tls_result, http_result, cname_chain)
    flags.is_cdn = is_cdn
    flags.cdn_provider = cdn_name

    # Split-horizon
    if internal_resolver:
        flags.split_horizon_mismatch = await check_split_horizon(
            domain, internal_resolver, timeout,
        )

    return flags
