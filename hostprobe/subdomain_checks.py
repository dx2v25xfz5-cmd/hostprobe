"""Subdomain enumeration via DNS brute-force of common prefixes."""

from __future__ import annotations

import asyncio
import logging

import dns.asyncresolver
import dns.resolver

from hostprobe.models import SubdomainEntry

logger = logging.getLogger("hostprobe")


async def _check_one_subdomain(
    fqdn: str,
    sem: asyncio.Semaphore,
    timeout: float = 5.0,
) -> SubdomainEntry:
    """Resolve a single subdomain FQDN."""
    async with sem:
        res = dns.asyncresolver.Resolver()
        res.lifetime = timeout

        addresses: list[str] = []
        cname_target: str | None = None
        resolved = False

        # Try A
        try:
            answer = await res.resolve(fqdn, "A")
            addresses.extend(rdata.to_text() for rdata in answer)
            resolved = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.resolver.LifetimeTimeout):
            pass
        except Exception as exc:
            logger.debug("Subdomain A query failed for %s: %s", fqdn, exc)

        # Try AAAA if no A
        if not addresses:
            try:
                answer = await res.resolve(fqdn, "AAAA")
                addresses.extend(rdata.to_text() for rdata in answer)
                resolved = True
            except Exception:
                pass

        # Check for CNAME
        try:
            answer = await res.resolve(fqdn, "CNAME")
            cname_target = answer[0].target.to_text().rstrip(".")
            resolved = True
        except Exception:
            pass

        return SubdomainEntry(
            fqdn=fqdn,
            resolved=resolved,
            addresses=addresses,
            cname_target=cname_target,
        )


async def check_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
    extra_subdomains: set[str] | None = None,
    concurrency: int = 20,
    timeout: float = 5.0,
) -> list[SubdomainEntry]:
    """Enumerate subdomains for *domain* using a wordlist + any extras from CT.

    Parameters
    ----------
    domain:
        The apex domain to test subdomains against.
    wordlist:
        List of subdomain prefixes to test (e.g. ["www", "api"]).
    extra_subdomains:
        Additional FQDNs discovered through CT logs or passive DNS.
    concurrency:
        How many DNS lookups to run concurrently.
    timeout:
        DNS query timeout per subdomain.

    Returns
    -------
    list[SubdomainEntry]
        Results for each subdomain, including those that didn't resolve.
    """
    from hostprobe.config import DEFAULT_SUBDOMAINS

    prefixes = wordlist or DEFAULT_SUBDOMAINS

    # Build FQDN set
    fqdns: set[str] = set()
    for prefix in prefixes:
        fqdn = f"{prefix}.{domain}"
        fqdns.add(fqdn)

    # Merge CT-discovered subdomains
    if extra_subdomains:
        for sub in extra_subdomains:
            # Ensure they belong to the target domain
            if sub.endswith(f".{domain}") or sub == domain:
                fqdns.add(sub)

    sem = asyncio.Semaphore(concurrency)
    tasks = [_check_one_subdomain(fqdn, sem, timeout) for fqdn in sorted(fqdns)]
    results = await asyncio.gather(*tasks)

    # Sort: resolved first, then alphabetical
    return sorted(results, key=lambda e: (not e.resolved, e.fqdn))
