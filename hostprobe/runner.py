"""Decision tree orchestrator — walks the complete host discovery workflow."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from hostprobe.cloud_checks import detect_cloud_artifacts, detect_dangling_cnames
from hostprobe.config import Config
from hostprobe.decommission import check_decommission_signals
from hostprobe.dns_checks import (
    check_all_records,
    check_dnssec,
    classify_dns,
    interpret_records,
    trace_cname_chain,
)
from hostprobe.edge_cases import detect_cdn, detect_wildcard, run_edge_case_checks
from hostprobe.host_discovery import (
    grab_banner,
    nmap_syn_scan,
    probe_http,
    probe_icmp,
    probe_ports,
    probe_smtp,
    probe_tls,
)
from hostprobe.models import (
    DNSClassification,
    DomainReport,
    EdgeCaseFlags,
    PortState,
    Verdict,
)
from hostprobe.passive_recon import passive_recon
from hostprobe.subdomain_checks import check_subdomains
from hostprobe.whois_check import check_whois

logger = logging.getLogger("hostprobe")


class ProgressCallback:
    """Simple progress reporter — override or replace for custom UI."""

    def phase(self, phase_name: str, detail: str = "") -> None:
        """Called when entering a new scan phase."""
        pass

    def done(self) -> None:
        """Called when scan is complete."""
        pass


async def analyze_domain(
    domain: str,
    config: Config,
    progress: ProgressCallback | None = None,
) -> DomainReport:
    """Run the full decision tree against *domain* and return a DomainReport."""
    prog = progress or ProgressCallback()
    report = DomainReport(domain=domain, verdict=Verdict.LIKELY_DEAD)
    report.scan_started = datetime.now(timezone.utc)
    reasoning: list[str] = []

    timeout = config.timeout

    # ==================================================================
    # PHASE 1 — DNS + WHOIS + CNAME + DNSSEC (concurrent)
    # ==================================================================
    prog.phase("DNS", "Classifying DNS and checking records")

    dns_task = classify_dns(domain, config.resolvers, timeout)
    records_task = check_all_records(domain, timeout)
    whois_task = check_whois(domain)
    cname_task = trace_cname_chain(domain, timeout)
    dnssec_task = check_dnssec(domain, timeout)

    results = await asyncio.gather(
        dns_task, records_task, whois_task, cname_task, dnssec_task,
        return_exceptions=True,
    )

    # Unpack — handle any exceptions gracefully
    dns_result = results[0] if not isinstance(results[0], BaseException) else None
    all_records = results[1] if not isinstance(results[1], BaseException) else {}
    whois_result = results[2] if not isinstance(results[2], BaseException) else None
    cname_chain = results[3] if not isinstance(results[3], BaseException) else []
    dnssec_status = results[4] if not isinstance(results[4], BaseException) else "unsigned"

    # Merge records into dns_result
    if dns_result and isinstance(all_records, dict):
        for rtype, vals in all_records.items():
            if vals:
                dns_result.records[rtype] = vals
        dns_result.dnssec_status = dnssec_status if isinstance(dnssec_status, str) else "unsigned"
        dns_result.cname_chain = cname_chain if isinstance(cname_chain, list) else []

    report.dns = dns_result
    report.whois = whois_result

    # Record interpretations
    if isinstance(all_records, dict):
        interpretations = interpret_records(all_records)
        reasoning.extend(interpretations)

    # ------------------------------------------------------------------
    # Decision Point A — WHOIS
    # ------------------------------------------------------------------
    if whois_result:
        if not whois_result.registered:
            reasoning.append("WHOIS: domain is NOT registered — strong dead signal")
        elif whois_result.recently_expired:
            reasoning.append("WHOIS: domain recently expired — infrastructure may linger")
        else:
            reasoning.append(f"WHOIS: domain registered (registrar: {whois_result.registrar or 'unknown'})")

    # ------------------------------------------------------------------
    # Decision Point B — DNS Classification
    # ------------------------------------------------------------------
    classification = dns_result.classification if dns_result else DNSClassification.SERVFAIL
    reasoning.append(f"DNS classification: {classification.value}")

    if isinstance(dnssec_status, str) and dnssec_status != "unsigned":
        reasoning.append(f"DNSSEC status: {dnssec_status}")

    if isinstance(cname_chain, list) and cname_chain:
        reasoning.append(f"CNAME chain: {domain} → {' → '.join(cname_chain)}")

    # Collect IPs to probe
    probe_targets: list[str] = []
    if dns_result:
        probe_targets.extend(dns_result.records.get("A", []))
        # We'll probe IPv6 separately in edge cases

    if classification == DNSClassification.RESOLVED and probe_targets:
        reasoning.append(f"Domain resolves to {', '.join(probe_targets)}")
        # Skip to Phase 2 — host discovery

    elif classification == DNSClassification.NXDOMAIN:
        reasoning.append("Domain returned NXDOMAIN — checking subdomains and passive data")
        # Phase 1b

    elif classification == DNSClassification.SERVFAIL:
        if isinstance(dnssec_status, str) and dnssec_status == "invalid":
            reasoning.append("SERVFAIL caused by DNSSEC validation failure")
        else:
            reasoning.append("SERVFAIL — possible broken delegation, offline NS, or zone misconfiguration")
        report.verdict = Verdict.INVESTIGATE
        # Still do passive + subdomain checks

    elif classification == DNSClassification.NOERROR_NODATA:
        reasoning.append("NOERROR with no A record — domain exists but has no host record")
        aaaa = dns_result.records.get("AAAA", []) if dns_result else []
        mx = dns_result.records.get("MX", []) if dns_result else []
        txt = dns_result.records.get("TXT", []) if dns_result else []

        if aaaa:
            reasoning.append(f"AAAA records found: {', '.join(aaaa)} — IPv6-only host")
            probe_targets.extend(aaaa)
        elif mx:
            reasoning.append("MX records present — will test SMTP")
        elif txt and not aaaa and not mx:
            reasoning.append("Only TXT records — domain active for verification, no host infrastructure")
            report.verdict = Verdict.PARTIAL

    # ==================================================================
    # PHASE 1b — Subdomains + Passive Recon (if NXDOMAIN / SERVFAIL / NODATA)
    # ==================================================================
    passive_result = None
    subdomain_results = []
    is_wildcard = False

    if not probe_targets or classification in (
        DNSClassification.NXDOMAIN,
        DNSClassification.SERVFAIL,
        DNSClassification.NOERROR_NODATA,
    ):
        prog.phase("Passive", "Checking subdomains, CT logs, and passive DNS")

        passive_task = passive_recon(
            domain,
            skip=config.skip_passive,
            securitytrails_key=config.securitytrails_api_key,
            virustotal_key=config.virustotal_api_key,
            timeout=max(timeout, 15.0),
        )
        wildcard_task = detect_wildcard(domain, timeout)

        p_results = await asyncio.gather(passive_task, wildcard_task, return_exceptions=True)

        passive_result = p_results[0] if not isinstance(p_results[0], BaseException) else None
        is_wildcard = p_results[1] if not isinstance(p_results[1], BaseException) else False

        # Subdomain check — merge CT-discovered subdomains
        extra_subs = passive_result.discovered_subdomains if passive_result else set()
        subdomain_results = await check_subdomains(
            domain,
            wordlist=config.subdomain_wordlist,
            extra_subdomains=extra_subs,
            concurrency=config.concurrency,
            timeout=timeout,
        )

        report.passive = passive_result
        report.subdomains = subdomain_results

        if is_wildcard:
            reasoning.append("WARNING: Wildcard DNS detected — subdomain results may be unreliable")

        # Check subdomain findings
        resolved_subs = [s for s in subdomain_results if s.resolved and not is_wildcard]
        if resolved_subs:
            sub_names = [s.fqdn for s in resolved_subs[:5]]
            reasoning.append(f"Subdomains resolve: {', '.join(sub_names)}"
                           + (f" (+{len(resolved_subs) - 5} more)" if len(resolved_subs) > 5 else ""))
            # Pivot: collect IPs from resolved subdomains
            for sub in resolved_subs:
                probe_targets.extend(sub.addresses)

        # Check CT entries
        if passive_result and passive_result.ct_entries:
            recent = [e for e in passive_result.ct_entries if e.is_recent]
            reasoning.append(
                f"CT logs: {len(passive_result.ct_entries)} certificates found "
                f"({len(recent)} recent)"
            )
        elif passive_result:
            reasoning.append("CT logs: no certificates found")

        # STOP condition check
        if classification == DNSClassification.NXDOMAIN:
            no_subdomains = not resolved_subs
            no_ct = not (passive_result and passive_result.ct_entries)
            no_passive = not (passive_result and passive_result.passive_dns_hits)
            unregistered = whois_result and not whois_result.registered

            if no_subdomains and no_ct and no_passive and unregistered:
                reasoning.append("STOP: NXDOMAIN + unregistered + no subdomains + no CT + no passive DNS")
                reasoning.append("Conclusion: no reachable infrastructure exists")
                report.verdict = Verdict.LIKELY_DEAD
                report.reasoning = reasoning
                _finalize(report)
                prog.done()
                return report
            elif no_subdomains and no_ct and no_passive:
                reasoning.append("STOP: NXDOMAIN + no subdomains + no CT + no passive DNS")
                report.verdict = Verdict.LIKELY_DEAD
                report.reasoning = reasoning
                _finalize(report)
                prog.done()
                return report
    else:
        # Domain resolved — still do passive recon in background
        if not config.skip_passive:
            passive_result = await passive_recon(
                domain,
                skip=config.skip_passive,
                securitytrails_key=config.securitytrails_api_key,
                virustotal_key=config.virustotal_api_key,
                timeout=max(timeout, 15.0),
            )
            report.passive = passive_result

    # Deduplicate probe targets
    probe_targets = list(set(probe_targets))

    # ==================================================================
    # PHASE 2 — Host Discovery (if we have targets)
    # ==================================================================
    if probe_targets:
        prog.phase("Discovery", f"Probing {len(probe_targets)} target(s)")

        # Pick primary target for detailed probing
        primary = probe_targets[0]

        # Concurrent probes
        icmp_task = probe_icmp(primary, timeout)

        if config.use_nmap:
            port_task = nmap_syn_scan(primary, config.ports, timeout=30.0)
        else:
            port_task = probe_ports(primary, config.ports, timeout)

        tls_task = probe_tls(primary, 443, timeout, domain=domain)

        # HTTP on both 443 and 80
        http_443_task = probe_http(primary, 443, use_tls=True, timeout=timeout, domain=domain)
        http_80_task = probe_http(primary, 80, use_tls=False, timeout=timeout, domain=domain)

        disc_results = await asyncio.gather(
            icmp_task, port_task, tls_task, http_443_task, http_80_task,
            return_exceptions=True,
        )

        # ICMP
        if not isinstance(disc_results[0], BaseException):
            report.icmp = disc_results[0]
            if report.icmp.reachable:
                reasoning.append(f"ICMP: host reachable (latency: {report.icmp.latency_ms}ms)")
            else:
                reasoning.append("ICMP: no response (may be filtered — inconclusive)")

        # Ports
        if not isinstance(disc_results[1], BaseException):
            report.port_probes = disc_results[1] if isinstance(disc_results[1], list) else []
            for pp in report.port_probes:
                if pp.state == PortState.OPEN:
                    reasoning.append(f"TCP {pp.port}: OPEN (SYN-ACK) — host alive")
                elif pp.state == PortState.CLOSED:
                    reasoning.append(f"TCP {pp.port}: CLOSED (RST) — host alive, port not listening")
                elif pp.state == PortState.FILTERED:
                    reasoning.append(f"TCP {pp.port}: FILTERED (timeout)")

        # TLS
        if not isinstance(disc_results[2], BaseException):
            report.tls = disc_results[2]
            if report.tls.handshake_ok:
                reasoning.append(f"TLS handshake: SUCCESS — certificate presented")
                if report.tls.cert_cn:
                    reasoning.append(f"  CN: {report.tls.cert_cn}")
                if report.tls.cert_san_list:
                    reasoning.append(f"  SANs: {', '.join(report.tls.cert_san_list[:5])}")
                if report.tls.cert_matches_domain:
                    reasoning.append(f"  Certificate matches {domain}")
                else:
                    reasoning.append(f"  WARNING: Certificate does NOT match {domain}")
                if report.tls.is_expired:
                    reasoning.append("  WARNING: Certificate is EXPIRED — possible decommission")
                elif report.tls.expires_soon:
                    reasoning.append("  NOTE: Certificate expires within 30 days")
            else:
                reason = report.tls.error_reason or "unknown"
                reasoning.append(f"TLS handshake: FAILED ({reason})")

        # HTTP
        http_result = None
        if not isinstance(disc_results[3], BaseException) and disc_results[3].status_code:
            http_result = disc_results[3]
            report.http = http_result
            reasoning.append(f"HTTP (443): {http_result.status_code} (server: {http_result.server_header or '?'})")
            if http_result.redirect_target:
                reasoning.append(f"  Redirects to: {http_result.redirect_target}")
        elif not isinstance(disc_results[4], BaseException) and disc_results[4].status_code:
            http_result = disc_results[4]
            report.http = http_result
            reasoning.append(f"HTTP (80): {http_result.status_code} (server: {http_result.server_header or '?'})")

        # SMTP (if MX records exist)
        mx_records = dns_result.records.get("MX", []) if dns_result else []
        if mx_records:
            prog.phase("SMTP", "Validating mail infrastructure")
            # Extract MX host from "10 mail.example.com." format
            mx_host = mx_records[0].split()[-1].rstrip(".")
            smtp_result = await probe_smtp(mx_host, 25, timeout=10.0)
            report.smtp = smtp_result
            if smtp_result.responsive:
                reasoning.append(f"SMTP: responsive (banner: {smtp_result.banner[:60]})")
                if smtp_result.supports_starttls:
                    reasoning.append("  Supports STARTTLS")
            else:
                reasoning.append("SMTP: not responsive or connection refused")

        # Banner grabs on open ports
        open_ports = [pp.port for pp in report.port_probes if pp.state == PortState.OPEN]
        banner_ports = [p for p in open_ports if p not in (443, 80)]  # skip HTTP ports
        if banner_ports:
            banner_tasks = [grab_banner(primary, p, timeout) for p in banner_ports]
            banner_results = await asyncio.gather(*banner_tasks, return_exceptions=True)
            for br in banner_results:
                if not isinstance(br, BaseException) and br.banner_text:
                    report.banners.append(br)
                    reasoning.append(
                        f"Banner {br.port}: {br.banner_text[:60]} "
                        f"(protocol: {br.protocol_guess or '?'})"
                    )

        # ------- Layered verdict -------
        any_open = any(pp.state == PortState.OPEN for pp in report.port_probes)
        any_closed = any(pp.state == PortState.CLOSED for pp in report.port_probes)
        all_filtered = all(pp.state == PortState.FILTERED for pp in report.port_probes) if report.port_probes else False
        has_http = http_result and http_result.status_code
        has_tls = report.tls and report.tls.handshake_ok

        if has_http:
            report.verdict = Verdict.ALIVE
            reasoning.append("VERDICT: ALIVE — application responded to HTTP")
        elif has_tls:
            report.verdict = Verdict.ALIVE
            reasoning.append("VERDICT: ALIVE — TLS handshake succeeded, certificate presented")
        elif any_open:
            report.verdict = Verdict.ALIVE
            reasoning.append("VERDICT: ALIVE — TCP port(s) open (SYN-ACK received)")
        elif any_closed:
            report.verdict = Verdict.ALIVE
            reasoning.append("VERDICT: ALIVE — TCP RST received (host is up, port closed)")
        elif all_filtered:
            report.verdict = Verdict.FILTERED
            reasoning.append("VERDICT: FILTERED — all probed ports timed out (firewall or dead)")
        elif report.smtp and report.smtp.responsive:
            report.verdict = Verdict.ALIVE
            reasoning.append("VERDICT: ALIVE — SMTP responsive")

    elif classification == DNSClassification.NOERROR_NODATA:
        # No probe targets but domain exists (TXT/MX only)
        mx = dns_result.records.get("MX", []) if dns_result else []
        if mx:
            mx_host = mx[0].split()[-1].rstrip(".")
            prog.phase("SMTP", "Testing mail infrastructure")
            smtp_result = await probe_smtp(mx_host, 25, timeout=10.0)
            report.smtp = smtp_result
            if smtp_result.responsive:
                report.verdict = Verdict.ALIVE
                reasoning.append("VERDICT: ALIVE — SMTP responsive on MX host")
            else:
                report.verdict = Verdict.PARTIAL
                reasoning.append("VERDICT: PARTIAL — MX records exist but SMTP not responsive")
        else:
            report.verdict = Verdict.PARTIAL
            reasoning.append("VERDICT: PARTIAL — domain exists (has records) but no reachable host")

    # ==================================================================
    # PHASE 3 — Edge Cases + Cloud (concurrent)
    # ==================================================================
    prog.phase("Edge", "Checking CDN, cloud artifacts, IPv6, wildcard")

    edge_flags = await run_edge_case_checks(
        domain,
        dns_result.records if dns_result else {},
        report.tls,
        report.http,
        cname_chain if isinstance(cname_chain, list) else None,
        internal_resolver=config.internal_resolver,
        timeout=timeout,
    )

    # Cloud artifacts
    cname_chains_map = {domain: cname_chain} if isinstance(cname_chain, list) and cname_chain else {}
    cloud_provider, cloud_artifacts = detect_cloud_artifacts(
        cname_chains=cname_chains_map,
        subdomain_results=subdomain_results if subdomain_results else None,
    )
    edge_flags.cloud_provider = cloud_provider
    edge_flags.cloud_artifacts = cloud_artifacts

    # Dangling CNAMEs
    dangling = detect_dangling_cnames(subdomain_results if subdomain_results else None)
    edge_flags.dangling_cnames = dangling

    report.edge_cases = edge_flags

    if edge_flags.is_cdn:
        reasoning.append(f"CDN detected: {edge_flags.cdn_provider} — edge may respond even if origin is down")
    if edge_flags.has_ipv6:
        if edge_flags.ipv6_reachable:
            reasoning.append("IPv6: reachable")
            if report.verdict != Verdict.ALIVE:
                report.verdict = Verdict.ALIVE
                reasoning.append("VERDICT updated: ALIVE — IPv6 host reachable")
        else:
            reasoning.append("IPv6: AAAA record exists but host not reachable on IPv6")
    if edge_flags.split_horizon_mismatch:
        reasoning.append("SPLIT-HORIZON: public and internal DNS results differ")
    if edge_flags.dangling_cnames:
        for dc in edge_flags.dangling_cnames:
            reasoning.append(f"DANGLING CNAME: {dc}")
    if cloud_artifacts:
        for artifact in cloud_artifacts:
            reasoning.append(f"Cloud: {artifact}")

    # ==================================================================
    # PHASE 4 — Decommission Analysis
    # ==================================================================
    if report.verdict in (Verdict.LIKELY_DEAD, Verdict.FILTERED, Verdict.PARTIAL):
        if passive_result and (passive_result.ct_entries or passive_result.passive_dns_hits):
            prog.phase("Decommission", "Checking for recently decommissioned infrastructure")
            decomm = await check_decommission_signals(
                domain, dns_result, passive_result, whois_result, timeout,
            )
            report.decommission = decomm
            if decomm.likely_decommissioned:
                report.verdict = Verdict.RECENTLY_DECOMMISSIONED
                reasoning.append("VERDICT updated: RECENTLY DECOMMISSIONED")
                for ev in decomm.evidence:
                    reasoning.append(f"  Evidence: {ev}")

    # ==================================================================
    # PHASE 5 — Final verdict
    # ==================================================================
    report.reasoning = reasoning
    _finalize(report)
    prog.done()

    return report


def _finalize(report: DomainReport) -> None:
    """Set scan timing metadata."""
    report.scan_finished = datetime.now(timezone.utc)
    if report.scan_started:
        report.scan_duration_s = round(
            (report.scan_finished - report.scan_started).total_seconds(), 2
        )
