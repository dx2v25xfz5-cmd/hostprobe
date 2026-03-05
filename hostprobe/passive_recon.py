"""Passive recon: Certificate Transparency, passive DNS, Shodan, Censys."""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

from hostprobe.models import CTEntry, PassiveResult
from hostprobe.utils import random_user_agent, retry_with_backoff

logger = logging.getLogger("hostprobe")


# ---------------------------------------------------------------------------
# Certificate Transparency (crt.sh — free, no API key)
# ---------------------------------------------------------------------------

async def search_ct_logs(
    domain: str,
    timeout: float = 15.0,
) -> list[CTEntry]:
    """Query crt.sh for certificates issued for *domain* and *.domain.

    Uses retry_with_backoff because crt.sh is frequently slow / rate-limits.
    """

    async def _fetch() -> list[CTEntry]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        return await asyncio.to_thread(_fetch_sync, url, timeout)

    try:
        return await retry_with_backoff(
            _fetch,
            retries=3,
            base_delay=2.0,
            max_delay=15.0,
            exceptions=(OSError, asyncio.TimeoutError, urllib.error.URLError, Exception),
        )
    except Exception as exc:
        logger.warning("CT log search failed for %s: %s", domain, exc)
        return []


def _fetch_sync(url: str, timeout: float) -> list[CTEntry]:
    """Synchronous HTTP fetch + JSON parse for crt.sh."""
    req = urllib.request.Request(url, headers={"User-Agent": random_user_agent()})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode())

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=90)
    seen: set[str] = set()
    entries: list[CTEntry] = []

    for row in data:
        cn: str = row.get("common_name", "").lower().strip()
        if cn in seen:
            continue
        seen.add(cn)

        not_before = _parse_ct_date(row.get("not_before"))
        not_after = _parse_ct_date(row.get("not_after"))
        is_recent = bool(not_before and not_before > cutoff)

        entries.append(CTEntry(
            common_name=cn,
            issuer=row.get("issuer_name", ""),
            not_before=not_before,
            not_after=not_after,
            is_recent=is_recent,
        ))

    return entries


def _parse_ct_date(val: str | None) -> datetime | None:
    """Parse crt.sh timestamp (ISO-ish format)."""
    if not val:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


# ---------------------------------------------------------------------------
# Passive DNS — SecurityTrails (optional, needs API key)
# ---------------------------------------------------------------------------

async def check_securitytrails(
    domain: str,
    api_key: str,
    timeout: float = 10.0,
) -> list[dict]:
    """Query SecurityTrails for historical DNS data (subdomains + A records)."""
    try:
        import aiohttp
    except ImportError:
        logger.debug("aiohttp not available for SecurityTrails query")
        return []

    headers = {"APIKEY": api_key, "Accept": "application/json", "User-Agent": random_user_agent()}
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status != 200:
                    logger.debug("SecurityTrails returned %d for %s", resp.status, domain)
                    return []
                data = await resp.json()
                subs = data.get("subdomains", [])
                return [{"subdomain": f"{s}.{domain}", "source": "securitytrails"} for s in subs]
    except Exception as exc:
        logger.debug("SecurityTrails query failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Passive DNS — VirusTotal (optional, needs API key)
# ---------------------------------------------------------------------------

async def check_virustotal(
    domain: str,
    api_key: str,
    timeout: float = 10.0,
) -> list[dict]:
    """Query VirusTotal for domain resolutions."""
    try:
        import aiohttp
    except ImportError:
        logger.debug("aiohttp not available for VirusTotal query")
        return []

    headers = {"x-apikey": api_key, "Accept": "application/json", "User-Agent": random_user_agent()}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status != 200:
                    logger.debug("VirusTotal returned %d for %s", resp.status, domain)
                    return []
                data = await resp.json()
                results = []
                for item in data.get("data", []):
                    results.append({
                        "subdomain": item.get("id", ""),
                        "source": "virustotal",
                    })
                return results
    except Exception as exc:
        logger.debug("VirusTotal query failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Passive port/service data — Shodan (optional, needs API key)
# ---------------------------------------------------------------------------

async def check_shodan(
    domain: str,
    api_key: str,
    timeout: float = 10.0,
) -> list[dict]:
    """Query Shodan for host data (open ports, services, vulns)."""
    try:
        import aiohttp
    except ImportError:
        return []

    # Shodan requires searching by IP, so resolve first
    import dns.asyncresolver
    try:
        answer = await dns.asyncresolver.resolve(domain, "A")
        ip = answer[0].to_text()
    except Exception:
        logger.debug("Could not resolve %s for Shodan lookup", domain)
        return []

    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    headers = {"User-Agent": random_user_agent()}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status != 200:
                    logger.debug("Shodan returned %d for %s", resp.status, ip)
                    return []
                data = await resp.json()
                results = []
                for port_data in data.get("data", []):
                    results.append({
                        "port": port_data.get("port"),
                        "transport": port_data.get("transport", "tcp"),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "banner": (port_data.get("data", ""))[:200],
                        "source": "shodan",
                    })
                return results
    except Exception as exc:
        logger.debug("Shodan query failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Passive data — Censys (optional, needs API ID + secret)
# ---------------------------------------------------------------------------

async def check_censys(
    domain: str,
    api_id: str,
    api_secret: str,
    timeout: float = 10.0,
) -> list[dict]:
    """Query Censys Search 2.0 API for host data."""
    try:
        import aiohttp
    except ImportError:
        return []

    url = f"https://search.censys.io/api/v2/hosts/search?q={domain}&per_page=25"
    headers = {"User-Agent": random_user_agent(), "Accept": "application/json"}
    auth = aiohttp.BasicAuth(api_id, api_secret)

    try:
        async with aiohttp.ClientSession(auth=auth) as session:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status != 200:
                    logger.debug("Censys returned %d for %s", resp.status, domain)
                    return []
                data = await resp.json()
                results = []
                for hit in data.get("result", {}).get("hits", []):
                    ip = hit.get("ip", "")
                    for svc in hit.get("services", []):
                        results.append({
                            "ip": ip,
                            "port": svc.get("port"),
                            "service_name": svc.get("service_name", ""),
                            "transport": svc.get("transport_protocol", "TCP"),
                            "source": "censys",
                        })
                return results
    except Exception as exc:
        logger.debug("Censys query failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Aggregate passive recon
# ---------------------------------------------------------------------------

async def passive_recon(
    domain: str,
    *,
    skip: bool = False,
    securitytrails_key: str | None = None,
    virustotal_key: str | None = None,
    shodan_key: str | None = None,
    censys_id: str | None = None,
    censys_secret: str | None = None,
    timeout: float = 15.0,
) -> PassiveResult:
    """Run all passive recon sources and aggregate results."""
    if skip:
        return PassiveResult()

    result = PassiveResult()

    # CT logs (always — free, no key)
    ct_task = search_ct_logs(domain, timeout=timeout)

    # Build task list
    tasks: list[asyncio.Task | asyncio.Future] = [asyncio.ensure_future(ct_task)]
    has_st = bool(securitytrails_key)
    has_vt = bool(virustotal_key)
    has_shodan = bool(shodan_key)
    has_censys = bool(censys_id and censys_secret)
    if has_st:
        tasks.append(asyncio.ensure_future(
            check_securitytrails(domain, securitytrails_key, timeout=timeout)  # type: ignore
        ))
    if has_vt:
        tasks.append(asyncio.ensure_future(
            check_virustotal(domain, virustotal_key, timeout=timeout)  # type: ignore
        ))
    if has_shodan:
        tasks.append(asyncio.ensure_future(
            check_shodan(domain, shodan_key, timeout=timeout)  # type: ignore
        ))
    if has_censys:
        tasks.append(asyncio.ensure_future(
            check_censys(domain, censys_id, censys_secret, timeout=timeout)  # type: ignore
        ))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # CT entries (always index 0)
    if not isinstance(results[0], BaseException):
        result.ct_entries = results[0]  # type: ignore

    # Passive DNS hits
    idx = 1
    for has in [has_st, has_vt, has_shodan, has_censys]:
        if has and idx < len(results):
            if not isinstance(results[idx], BaseException):
                result.passive_dns_hits.extend(results[idx])  # type: ignore
            idx += 1

    # Extract discovered subdomains from CT entries
    for entry in result.ct_entries:
        cn = entry.common_name
        if cn.startswith("*."):
            cn = cn[2:]
        if cn.endswith(f".{domain}") or cn == domain:
            result.discovered_subdomains.add(cn)

    # And from passive DNS hits
    for hit in result.passive_dns_hits:
        sub = hit.get("subdomain", "")
        if sub.endswith(f".{domain}") or sub == domain:
            result.discovered_subdomains.add(sub)

    logger.debug(
        "Passive recon for %s: %d CT entries, %d passive DNS hits, %d subdomains",
        domain, len(result.ct_entries), len(result.passive_dns_hits),
        len(result.discovered_subdomains),
    )

    return result
