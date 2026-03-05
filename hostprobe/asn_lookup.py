"""ASN and IP geolocation lookup via public APIs."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from hostprobe.models import ASNInfo

logger = logging.getLogger("hostprobe")

# Known cloud ASN ranges (by org name substring)
_CLOUD_ASNS: dict[str, str] = {
    "GOOGLE": "GCP",
    "CLOUDFLARENET": "Cloudflare",
    "AMAZON": "AWS",
    "MICROSOFT": "Azure",
    "DIGITALOCEAN": "DigitalOcean",
    "LINODE": "Linode/Akamai",
    "OVH": "OVH",
    "HETZNER": "Hetzner",
    "ORACLE": "Oracle Cloud",
    "ALIBABA": "Alibaba Cloud",
    "TENCENT": "Tencent Cloud",
    "FASTLY": "Fastly",
    "AKAMAI": "Akamai",
    "VULTR": "Vultr",
}


async def lookup_asn(
    ip: str,
    timeout: float = 5.0,
) -> ASNInfo:
    """Look up ASN, ISP, and geolocation for an IP address.

    Uses the free ip-api.com JSON endpoint (no API key required,
    rate-limited to ~45 req/min).

    Falls back to Team Cymru DNS-based ASN lookup if ip-api fails.
    """
    result = ASNInfo(ip=ip)

    # --- Method 1: ip-api.com ---
    try:
        result = await _query_ip_api(ip, timeout)
        if result.asn:
            return result
    except Exception as exc:
        logger.debug("ip-api.com lookup failed for %s: %s", ip, exc)

    # --- Method 2: Team Cymru DNS ---
    try:
        result = await _query_cymru(ip, timeout)
    except Exception as exc:
        logger.debug("Team Cymru lookup failed for %s: %s", ip, exc)

    return result


async def _query_ip_api(ip: str, timeout: float) -> ASNInfo:
    """Query ip-api.com for IP details."""
    import aiohttp

    url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,asname"

    async with aiohttp.ClientSession() as session:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status != 200:
                return ASNInfo(ip=ip)
            data = await resp.json()

    if data.get("status") != "success":
        return ASNInfo(ip=ip)

    # Parse ASN number from "AS12345 Org Name" format
    as_field = data.get("as", "")
    asn_num = None
    if as_field.startswith("AS"):
        try:
            asn_num = int(as_field.split()[0][2:])
        except (ValueError, IndexError):
            pass

    asn_org = data.get("asname", data.get("org", ""))
    isp = data.get("isp", "")

    # Cloud detection
    is_cloud = False
    cloud_provider = None
    org_upper = (asn_org or "").upper()
    for keyword, provider in _CLOUD_ASNS.items():
        if keyword in org_upper:
            is_cloud = True
            cloud_provider = provider
            break

    return ASNInfo(
        ip=ip,
        asn=asn_num,
        asn_org=asn_org,
        isp=isp,
        country=data.get("country"),
        city=data.get("city"),
        is_cloud=is_cloud,
        cloud_provider=cloud_provider,
    )


async def _query_cymru(ip: str, timeout: float) -> ASNInfo:
    """Query Team Cymru via DNS TXT for ASN info.

    Reverse the IP and query <reversed>.origin.asn.cymru.com TXT.
    """
    import dns.asyncresolver
    import dns.resolver

    # Reverse IP octets
    parts = ip.split(".")
    if len(parts) != 4:
        return ASNInfo(ip=ip)

    reversed_ip = ".".join(reversed(parts))
    query = f"{reversed_ip}.origin.asn.cymru.com"

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    try:
        answer = await resolver.resolve(query, "TXT")
        for rdata in answer:
            txt = rdata.to_text().strip('"')
            # Format: "ASN | IP/Prefix | CC | Registry | Allocated"
            fields = [f.strip() for f in txt.split("|")]
            if len(fields) >= 3:
                asn_num = int(fields[0]) if fields[0].isdigit() else None
                country = fields[2] if len(fields) > 2 else None

                # Get ASN name from AS<num>.asn.cymru.com
                asn_org = None
                if asn_num:
                    try:
                        name_q = f"AS{asn_num}.asn.cymru.com"
                        name_answer = await resolver.resolve(name_q, "TXT")
                        for nr in name_answer:
                            name_txt = nr.to_text().strip('"')
                            name_fields = [f.strip() for f in name_txt.split("|")]
                            if len(name_fields) >= 5:
                                asn_org = name_fields[4]
                    except Exception:
                        pass

                # Cloud detection
                is_cloud = False
                cloud_provider = None
                if asn_org:
                    org_upper = asn_org.upper()
                    for keyword, provider in _CLOUD_ASNS.items():
                        if keyword in org_upper:
                            is_cloud = True
                            cloud_provider = provider
                            break

                return ASNInfo(
                    ip=ip,
                    asn=asn_num,
                    asn_org=asn_org,
                    country=country,
                    is_cloud=is_cloud,
                    cloud_provider=cloud_provider,
                )
    except Exception as exc:
        logger.debug("Cymru DNS query failed: %s", exc)

    return ASNInfo(ip=ip)


async def lookup_multiple_asns(
    ips: list[str],
    timeout: float = 5.0,
) -> list[ASNInfo]:
    """Look up ASN info for multiple IPs concurrently."""
    if not ips:
        return []
    tasks = [lookup_asn(ip, timeout) for ip in ips[:5]]  # limit to first 5
    return list(await asyncio.gather(*tasks, return_exceptions=False))
