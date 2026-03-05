"""Recently-decommissioned infrastructure correlation logic."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from hostprobe.models import (
    DecommissionSignals,
    DNSClassification,
    DNSResult,
    PassiveResult,
    TLSResult,
    WhoisResult,
)

logger = logging.getLogger("hostprobe")


async def check_decommission_signals(
    domain: str,
    dns_result: DNSResult | None,
    passive_result: PassiveResult | None,
    whois_result: WhoisResult | None,
    timeout: float = 5.0,
) -> DecommissionSignals:
    """Cross-reference passive data to determine if infrastructure was recently decommissioned.

    Signals checked:
        1. Domain is NXDOMAIN / unregistered NOW
        2. Passive DNS shows an IP within the last 7 days
        3. CT log shows certificate issued within 90 days
        4. WHOIS shows expired within 90 days
        5. If last_known_ip found: probe that IP directly for alive host + valid cert

    If >= 2 signals positive → likely_decommissioned = True.
    """
    signals = DecommissionSignals()
    now = datetime.now(timezone.utc)
    evidence: list[str] = []
    score = 0

    # --- Signal 1: domain doesn't resolve currently ---
    domain_dead_now = False
    if dns_result and dns_result.classification in (
        DNSClassification.NXDOMAIN,
        DNSClassification.NOERROR_NODATA,
    ):
        domain_dead_now = True
    if whois_result and not whois_result.registered:
        domain_dead_now = True

    if not domain_dead_now:
        # Domain resolves — not decommissioned
        return signals

    # --- Signal 2: recent passive DNS ---
    last_known_ip: str | None = None
    if passive_result:
        for hit in passive_result.passive_dns_hits:
            last_seen_str = hit.get("last_seen") or hit.get("resolve_date")
            if last_seen_str:
                try:
                    from datetime import datetime as dt
                    last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                    if (now - last_seen) < timedelta(days=7):
                        last_known_ip = hit.get("ip") or hit.get("address")
                        signals.passive_dns_last_seen = last_seen
                        evidence.append(
                            f"Passive DNS shows IP {last_known_ip} seen {last_seen.date()}"
                        )
                        score += 1
                        break
                except (ValueError, TypeError):
                    pass

    # --- Signal 3: recent CT certificate ---
    if passive_result and passive_result.ct_entries:
        recent_certs = [e for e in passive_result.ct_entries if e.is_recent]
        if recent_certs:
            most_recent = max(recent_certs, key=lambda e: e.not_before or datetime.min.replace(tzinfo=timezone.utc))
            evidence.append(
                f"Certificate for {most_recent.common_name} issued "
                f"{most_recent.not_before.date() if most_recent.not_before else '?'}"
            )
            score += 1

    # --- Signal 4: recently expired WHOIS ---
    if whois_result and whois_result.recently_expired:
        evidence.append(
            f"Domain expired {whois_result.expiry_date.date() if whois_result.expiry_date else 'recently'}"
        )
        score += 1

    # --- Signal 5: probe last known IP ---
    if last_known_ip:
        signals.last_known_ip = last_known_ip
        try:
            from hostprobe.host_discovery import probe_tcp, probe_tls

            tcp_result = await probe_tcp(last_known_ip, 443, timeout)
            if tcp_result.state.value in ("open", "closed"):
                evidence.append(
                    f"Last known IP {last_known_ip} still responds on port 443 "
                    f"(state: {tcp_result.state.value})"
                )
                score += 1

                # Check if cert still matches domain
                if tcp_result.state.value == "open":
                    tls = await probe_tls(last_known_ip, 443, timeout, domain=domain)
                    if tls.handshake_ok and tls.cert_matches_domain:
                        signals.cert_still_valid = True
                        evidence.append(
                            f"Certificate on {last_known_ip} still matches {domain}"
                        )
                        score += 1
        except Exception as exc:
            logger.debug("Decommission IP probe failed: %s", exc)

    # --- Verdict ---
    signals.evidence = evidence
    signals.likely_decommissioned = score >= 2

    if signals.likely_decommissioned:
        logger.info(
            "Domain %s likely recently decommissioned (score=%d): %s",
            domain, score, "; ".join(evidence),
        )

    return signals
