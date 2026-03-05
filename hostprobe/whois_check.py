"""WHOIS domain registration status check."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from hostprobe.models import WhoisResult

logger = logging.getLogger("hostprobe")


async def check_whois(domain: str) -> WhoisResult:
    """Check domain registration via WHOIS.

    Runs the synchronous python-whois library in an executor thread.
    """
    try:
        import whois as python_whois  # python-whois package
    except ImportError:
        logger.warning("python-whois not installed — skipping WHOIS check")
        return WhoisResult(
            registered=True,  # assume registered if we can't check
            registrar=None,
            creation_date=None,
            expiry_date=None,
            nameservers=[],
            recently_expired=False,
        )

    try:
        w = await asyncio.to_thread(python_whois.whois, domain)
    except Exception as exc:
        logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
        return WhoisResult(
            registered=True,  # default to assuming registered on error
            registrar=None,
            creation_date=None,
            expiry_date=None,
            nameservers=[],
            recently_expired=False,
        )

    # python-whois returns None or empty dict for unregistered domains
    registered = bool(w and w.get("domain_name"))

    # Normalize dates — python-whois sometimes returns lists of datetimes
    creation_date = _normalize_date(w.get("creation_date"))
    expiry_date = _normalize_date(w.get("expiration_date"))

    # Check recently expired
    recently_expired = False
    if expiry_date:
        now = datetime.now(timezone.utc)
        exp_aware = expiry_date if expiry_date.tzinfo else expiry_date.replace(tzinfo=timezone.utc)
        if exp_aware < now and (now - exp_aware) < timedelta(days=90):
            recently_expired = True

    # Nameservers
    ns_raw = w.get("name_servers") or []
    if isinstance(ns_raw, str):
        ns_raw = [ns_raw]
    nameservers = [str(ns).lower().rstrip(".") for ns in ns_raw if ns]

    registrar = w.get("registrar")
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None

    return WhoisResult(
        registered=registered,
        registrar=registrar,
        creation_date=creation_date,
        expiry_date=expiry_date,
        nameservers=nameservers,
        recently_expired=recently_expired,
    )


def _normalize_date(val: object) -> datetime | None:
    """Extract a single datetime from a whois field (may be list or str)."""
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if isinstance(val, datetime):
        return val
    return None
