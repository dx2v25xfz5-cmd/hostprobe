"""DNS classification, record enumeration, CNAME chain tracing, DNSSEC diagnostics."""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any

import aiohttp
import dns.asyncresolver
import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver

from hostprobe.models import DNSClassification, DNSResult
from hostprobe.utils import retry_with_backoff

logger = logging.getLogger("hostprobe")

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "CNAME")

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"


# ---------------------------------------------------------------------------
# DNS-over-HTTPS helper
# ---------------------------------------------------------------------------

async def _query_doh(
    domain: str,
    rdtype: str,
    timeout: float = 5.0,
) -> tuple[str, DNSClassification, list[str]]:
    """Resolve a DNS query via DNS-over-HTTPS (Cloudflare)."""
    try:
        q = dns.message.make_query(domain, rdtype)
        wire = q.to_wire()
        b64 = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
        url = f"{DOH_ENDPOINT}?dns={b64}"
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers={"Accept": "application/dns-message"},
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                data = await resp.read()
                msg = dns.message.from_wire(data)
                values: list[str] = []
                for rrset in msg.answer:
                    for rdata in rrset:
                        values.append(rdata.to_text())
                rcode = msg.rcode()
                if rcode == 3:  # NXDOMAIN
                    return ("DoH", DNSClassification.NXDOMAIN, [])
                if values:
                    return ("DoH", DNSClassification.RESOLVED, values)
                return ("DoH", DNSClassification.NOERROR_NODATA, [])
    except Exception as exc:
        logger.debug("DoH query failed for %s/%s: %s", domain, rdtype, exc)
        return ("DoH", DNSClassification.SERVFAIL, [])


# ---------------------------------------------------------------------------
# DNS Classification (Step 1)
# ---------------------------------------------------------------------------

async def _query_resolver(
    domain: str,
    rdtype: str,
    resolver_addr: str | None,
    timeout: float = 5.0,
) -> tuple[str, DNSClassification, list[str]]:
    """Query a single resolver and return (resolver_name, classification, values)."""
    res = dns.asyncresolver.Resolver()
    res.lifetime = timeout
    if resolver_addr:
        res.nameservers = [resolver_addr]

    name = resolver_addr or "system"
    try:
        answer = await res.resolve(domain, rdtype)
        values = [rdata.to_text() for rdata in answer]
        return (name, DNSClassification.RESOLVED, values)
    except dns.resolver.NXDOMAIN:
        return (name, DNSClassification.NXDOMAIN, [])
    except dns.resolver.NoAnswer:
        return (name, DNSClassification.NOERROR_NODATA, [])
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        return (name, DNSClassification.SERVFAIL, [])
    except Exception as exc:
        logger.debug("DNS query failed (%s, %s): %s", domain, name, exc)
        return (name, DNSClassification.SERVFAIL, [])


async def classify_dns(
    domain: str,
    resolvers: list[str] | None = None,
    timeout: float = 5.0,
    use_doh: bool = False,
) -> DNSResult:
    """Classify a domain's DNS status across multiple resolvers.

    Queries system default + all supplied resolvers concurrently.
    When *use_doh* is ``True``, also queries via DNS-over-HTTPS.
    Returns the consensus classification.
    """
    resolver_list: list[str | None] = [None]  # system default first
    if resolvers:
        resolver_list.extend(resolvers)

    tasks: list[Any] = [
        _query_resolver(domain, "A", r, timeout)
        for r in resolver_list
    ]
    if use_doh:
        tasks.append(_query_doh(domain, "A", timeout))
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect classifications across resolvers
    classifications: list[DNSClassification] = []
    all_values: list[str] = []
    queried: list[str] = []
    authoritative = False

    for r in results:
        if isinstance(r, BaseException):
            logger.debug("Resolver error: %s", r)
            continue
        rname, cls, vals = r
        queried.append(rname)
        classifications.append(cls)
        all_values.extend(vals)

    # Consensus: if ANY resolver got RESOLVED, domain resolves
    if DNSClassification.RESOLVED in classifications:
        final_cls = DNSClassification.RESOLVED
    elif all(c == DNSClassification.NXDOMAIN for c in classifications):
        final_cls = DNSClassification.NXDOMAIN
    elif all(c == DNSClassification.NOERROR_NODATA for c in classifications):
        final_cls = DNSClassification.NOERROR_NODATA
    elif classifications:
        # Mixed signals — pick the most informative
        if DNSClassification.NOERROR_NODATA in classifications:
            final_cls = DNSClassification.NOERROR_NODATA
        else:
            final_cls = DNSClassification.SERVFAIL
    else:
        final_cls = DNSClassification.SERVFAIL

    # Also query authoritative NS if we can find one
    auth_values: list[str] = []
    try:
        auth_values, authoritative = await _query_authoritative(domain, timeout)
        if auth_values and final_cls != DNSClassification.RESOLVED:
            final_cls = DNSClassification.RESOLVED
            all_values.extend(auth_values)
    except Exception as exc:
        logger.debug("Authoritative query failed: %s", exc)

    # Build initial records — full enumeration happens in check_all_records
    records: dict[str, list[str]] = {t: [] for t in RECORD_TYPES}
    records["A"] = list(set(all_values + auth_values))

    rcode_map = {
        DNSClassification.RESOLVED: "NOERROR",
        DNSClassification.NXDOMAIN: "NXDOMAIN",
        DNSClassification.SERVFAIL: "SERVFAIL",
        DNSClassification.NOERROR_NODATA: "NOERROR",
    }

    return DNSResult(
        classification=final_cls,
        rcode=rcode_map.get(final_cls, "UNKNOWN"),
        records=records,
        resolvers_queried=queried,
        authoritative=authoritative,
        dnssec_status="unsigned",  # updated by check_dnssec
        cname_chain=[],            # updated by trace_cname_chain
    )


async def _query_authoritative(
    domain: str,
    timeout: float = 5.0,
) -> tuple[list[str], bool]:
    """Try to query the domain's authoritative nameserver directly."""
    res = dns.asyncresolver.Resolver()
    res.lifetime = timeout

    # Find NS records
    try:
        ns_answer = await res.resolve(domain, "NS")
    except Exception:
        # Try the parent zone
        parts = domain.split(".")
        if len(parts) > 2:
            parent = ".".join(parts[1:])
            try:
                ns_answer = await res.resolve(parent, "NS")
            except Exception:
                return ([], False)
        else:
            return ([], False)

    for ns_rdata in ns_answer:
        ns_host = ns_rdata.to_text().rstrip(".")
        try:
            # Resolve the NS hostname to an IP to use as nameserver
            ns_ips = await res.resolve(ns_host, "A")
            ns_ip = ns_ips[0].to_text()
        except Exception:
            continue

        auth_res = dns.asyncresolver.Resolver()
        auth_res.nameservers = [ns_ip]
        auth_res.lifetime = timeout
        try:
            answer = await auth_res.resolve(domain, "A")
            return ([rdata.to_text() for rdata in answer], True)
        except dns.resolver.NXDOMAIN:
            return ([], True)  # authoritative NXDOMAIN
        except Exception:
            continue

    return ([], False)


# ---------------------------------------------------------------------------
# All Record Types (Step 2)
# ---------------------------------------------------------------------------

async def _query_record_type(
    domain: str,
    rdtype: str,
    timeout: float = 5.0,
) -> tuple[str, list[str]]:
    """Query a single record type and return (type, values)."""
    res = dns.asyncresolver.Resolver()
    res.lifetime = timeout
    try:
        answer = await res.resolve(domain, rdtype)
        values: list[str] = []
        for rdata in answer:
            if rdtype == "MX":
                values.append(f"{rdata.preference} {rdata.exchange.to_text()}")
            elif rdtype == "SOA":
                values.append(
                    f"{rdata.mname.to_text()} {rdata.rname.to_text()} "
                    f"{rdata.serial} {rdata.refresh} {rdata.retry} "
                    f"{rdata.expire} {rdata.minimum}"
                )
            else:
                values.append(rdata.to_text())
        return (rdtype, values)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.resolver.LifetimeTimeout):
        return (rdtype, [])
    except Exception as exc:
        logger.debug("Record query %s/%s failed: %s", domain, rdtype, exc)
        return (rdtype, [])


async def check_all_records(
    domain: str,
    timeout: float = 5.0,
) -> dict[str, list[str]]:
    """Query all standard record types concurrently."""
    tasks = [_query_record_type(domain, rt, timeout) for rt in RECORD_TYPES]
    results = await asyncio.gather(*tasks)
    return {rdtype: vals for rdtype, vals in results}


def interpret_records(records: dict[str, list[str]]) -> list[str]:
    """Apply the interpretation matrix from the document.

    Returns a list of human-readable interpretations.
    """
    interpretations: list[str] = []

    if records.get("MX"):
        interpretations.append("MX records present — mail infrastructure likely alive")
    if records.get("TXT") and not any(records.get(t) for t in ("A", "AAAA", "MX")):
        interpretations.append("TXT records only — domain in use for verification (SPF/DMARC/etc.)")
    if records.get("NS") and records.get("SOA"):
        interpretations.append("NS + SOA present — zone exists, domain is active")
    if records.get("CAA"):
        interpretations.append("CAA records present — certificate issuance configured")
    if records.get("AAAA") and not records.get("A"):
        interpretations.append("AAAA records only — IPv6-only host")
    if records.get("AAAA") and records.get("A"):
        interpretations.append("Dual-stack (A + AAAA)")
    if records.get("SRV"):
        interpretations.append("SRV records present — service discovery configured")
    if records.get("CNAME"):
        interpretations.append(f"CNAME present — aliased to {records['CNAME'][0]}")

    return interpretations


# ---------------------------------------------------------------------------
# CNAME Chain Tracing
# ---------------------------------------------------------------------------

async def trace_cname_chain(
    domain: str,
    timeout: float = 5.0,
    max_depth: int = 10,
) -> list[str]:
    """Follow the CNAME chain until terminal A/AAAA or failure.

    Returns ordered list of CNAME hops, ending with terminal A/AAAA if found.
    """
    chain: list[str] = []
    current = domain
    res = dns.asyncresolver.Resolver()
    res.lifetime = timeout

    for _ in range(max_depth):
        try:
            answer = await res.resolve(current, "CNAME")
            target = answer[0].target.to_text().rstrip(".")
            chain.append(target)
            current = target
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # No more CNAMEs — try to resolve terminal as A/AAAA
            break
        except Exception:
            break

    # Try to resolve the terminal name
    if chain:
        try:
            answer = await res.resolve(current, "A")
            chain.append(answer[0].to_text())
        except Exception:
            try:
                answer = await res.resolve(current, "AAAA")
                chain.append(answer[0].to_text())
            except Exception:
                pass  # terminal doesn't resolve — could be dangling

    return chain


# ---------------------------------------------------------------------------
# DNSSEC Diagnostics
# ---------------------------------------------------------------------------

async def check_dnssec(
    domain: str,
    timeout: float = 5.0,
) -> str:
    """Check DNSSEC validation status.

    Returns:
        "valid"   — DNSSEC signatures validated (AD flag set)
        "invalid" — SERVFAIL with DO but success without → validation failure
        "unsigned" — no DNSSEC signatures present
    """
    # Query WITH DNSSEC validation (DO flag)
    res_do = dns.asyncresolver.Resolver()
    res_do.lifetime = timeout
    res_do.use_edns(edns=0, ednsflags=dns.flags.DO)

    # Query WITHOUT DNSSEC
    res_plain = dns.asyncresolver.Resolver()
    res_plain.lifetime = timeout

    do_ok = False
    do_ad = False
    plain_ok = False

    try:
        answer = await res_do.resolve(domain, "A")
        do_ok = True
        do_ad = bool(answer.response.flags & dns.flags.AD)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        do_ok = True  # valid response, just no data
    except Exception:
        do_ok = False

    try:
        await res_plain.resolve(domain, "A")
        plain_ok = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        plain_ok = True
    except Exception:
        plain_ok = False

    if do_ok and do_ad:
        return "valid"
    if not do_ok and plain_ok:
        return "invalid"  # DNSSEC validation failure
    return "unsigned"
