"""Subdomain enumeration via subfinder (primary) with DNS brute-force fallback."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil

import dns.asyncresolver
import dns.resolver

from hostprobe.models import SubdomainEntry
from hostprobe.utils import run_subprocess

logger = logging.getLogger("hostprobe")


# ---------------------------------------------------------------------------
# subfinder integration
# ---------------------------------------------------------------------------

def _has_subfinder() -> bool:
    """Check whether subfinder is on PATH."""
    return shutil.which("subfinder") is not None


async def _run_subfinder(
    domain: str,
    timeout: float = 60.0,
) -> set[str]:
    """Run subfinder and return discovered FQDNs.

    subfinder is invoked in silent JSON-lines mode so we can parse results
    reliably.  The ``-all`` flag enables all passive sources.
    """
    cmd = [
        "subfinder",
        "-d", domain,
        "-silent",
        "-json",
        "-all",
        "-timeout", str(max(int(timeout), 5)),
    ]

    try:
        rc, stdout, stderr = await run_subprocess(
            cmd,
            timeout=timeout + 10,   # give a bit of slack beyond subfinder's own timeout
        )
    except Exception as exc:
        logger.warning("subfinder execution failed: %s", exc)
        return set()

    fqdns: set[str] = set()

    if rc != 0:
        logger.debug("subfinder exited %d: %s", rc, stderr.strip()[:200])

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # subfinder -json outputs one JSON object per line
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                host = obj.get("host", "").strip().lower()
                if host:
                    fqdns.add(host)
            except json.JSONDecodeError:
                pass
        else:
            # Fallback: plain text (one FQDN per line) when -json fails
            candidate = line.strip().lower()
            if "." in candidate and candidate.endswith(f".{domain}") or candidate == domain:
                fqdns.add(candidate)

    logger.info("subfinder found %d subdomains for %s", len(fqdns), domain)
    return fqdns


# ---------------------------------------------------------------------------
# DNS resolution of discovered subdomains
# ---------------------------------------------------------------------------

async def _resolve_subdomain(
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


# ---------------------------------------------------------------------------
# DNS brute-force fallback
# ---------------------------------------------------------------------------

async def _brute_force_subdomains(
    domain: str,
    wordlist: list[str],
    concurrency: int,
    timeout: float,
) -> set[str]:
    """Resolve a wordlist of prefixes and return FQDNs that resolved."""
    sem = asyncio.Semaphore(concurrency)
    fqdns = [f"{prefix}.{domain}" for prefix in wordlist]
    tasks = [_resolve_subdomain(fqdn, sem, timeout) for fqdn in fqdns]
    results = await asyncio.gather(*tasks)
    return {entry.fqdn for entry in results if entry.resolved}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def check_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
    extra_subdomains: set[str] | None = None,
    concurrency: int = 20,
    timeout: float = 5.0,
) -> list[SubdomainEntry]:
    """Enumerate subdomains for *domain*.

    Strategy:
    1. If ``subfinder`` is installed, use it (fast, many passive sources).
    2. Merge in any CT-discovered subdomains from passive recon.
    3. Fall back to DNS brute-force of the wordlist if subfinder is absent.
    4. Resolve all discovered FQDNs for addresses / CNAME targets.

    Parameters
    ----------
    domain:
        The apex domain to test subdomains against.
    wordlist:
        List of subdomain prefixes for brute-force fallback.
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

    fqdns: set[str] = set()

    # --- Source 1: subfinder ---
    if _has_subfinder():
        logger.info("Using subfinder for subdomain enumeration")
        subfinder_results = await _run_subfinder(domain, timeout=max(timeout * 10, 30.0))
        fqdns.update(subfinder_results)
    else:
        logger.info("subfinder not found, falling back to DNS brute-force")
        prefixes = wordlist or DEFAULT_SUBDOMAINS
        for prefix in prefixes:
            fqdns.add(f"{prefix}.{domain}")

    # --- Source 2: CT / passive-discovered subdomains ---
    if extra_subdomains:
        for sub in extra_subdomains:
            if sub.endswith(f".{domain}") or sub == domain:
                fqdns.add(sub)

    if not fqdns:
        return []

    # --- Resolve everything ---
    sem = asyncio.Semaphore(concurrency)
    tasks = [_resolve_subdomain(fqdn, sem, timeout) for fqdn in sorted(fqdns)]
    results = await asyncio.gather(*tasks)

    # Sort: resolved first, then alphabetical
    return sorted(results, key=lambda e: (not e.resolved, e.fqdn))
