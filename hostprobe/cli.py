"""CLI argument parsing, entry point, and exit code mapping."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from hostprobe.config import Config, load_config
from hostprobe.models import Verdict
from hostprobe.output import (
    BatchProgress,
    TerminalProgress,
    format_csv,
    format_json,
    format_terminal,
    format_verdict_line,
)
from hostprobe.runner import analyze_domain
from hostprobe.utils import setup_logging


RUNTIME_ERROR_EXIT = 10


def build_parser():
    """Build the argparse parser."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="hostprobe",
        description=(
            "Host discovery & non-resolving domain assessment tool.\n"
            "Walks a structured decision tree to determine whether a host is alive,\n"
            "whether a domain truly has no backing infrastructure, and whether DNS\n"
            "failure is masking an active system."
        ),
        epilog=(
            "Exit codes: 0=ALIVE, 1=LIKELY_DEAD, 2=INVESTIGATE, 3=PARTIAL, "
            "4=FILTERED, 5=RECENTLY_DECOMMISSIONED, 10=ERROR\n\n"
            "Use only on systems you own or are explicitly authorized to assess."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "domain",
        nargs="?",
        help="Domain to analyze (e.g. example.com)",
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="File with one domain per line for batch processing",
    )

    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output JSON only (to stdout)",
    )
    output_group.add_argument(
        "--csv",
        action="store_true",
        dest="csv_output",
        help="Output CSV report (to stdout, or to file with -o)",
    )
    output_group.add_argument(
        "-o", "--output",
        type=str,
        dest="output_file",
        help="Write JSON results to file",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Debug logging to stderr",
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Verdict line only (no progress, no full report)",
    )

    scan_group = parser.add_argument_group("scan options")
    scan_group.add_argument(
        "--ports",
        type=str,
        default=None,
        help="Comma-separated port list (default: 443,80)",
    )
    scan_group.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Per-probe timeout in seconds (default: 5)",
    )
    scan_group.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="Max concurrent operations (default: 20)",
    )
    scan_group.add_argument(
        "--nmap",
        action="store_true",
        dest="use_nmap",
        help="Use nmap SYN scan (requires root + nmap installed)",
    )
    scan_group.add_argument(
        "--wordlist",
        type=str,
        help="Custom subdomain wordlist file (one prefix per line)",
    )
    scan_group.add_argument(
        "--skip-passive",
        action="store_true",
        dest="skip_passive",
        help="Skip CT log and passive DNS lookups",
    )
    scan_group.add_argument(
        "--internal-resolver",
        type=str,
        dest="internal_resolver",
        help="IP of internal DNS server for split-horizon testing",
    )
    scan_group.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config file (default: ~/.hostprobe.toml)",
    )

    return parser


def _parse_args(argv: list[str] | None = None) -> tuple[Config, list[str]]:
    """Parse CLI args and return (Config, list_of_domains)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.domain and not args.file:
        parser.error("either a domain argument or -f/--file is required")

    # Collect domains
    domains: list[str] = []
    if args.domain:
        domains.append(args.domain.strip().lower())
    if args.file:
        path = Path(args.file)
        if not path.exists():
            parser.error(f"file not found: {args.file}")
        domains.extend(
            line.strip().lower()
            for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        )

    if not domains:
        parser.error("no domains to scan")

    # Build CLI overrides dict
    overrides: dict = {}
    if args.ports:
        overrides["ports"] = [int(p.strip()) for p in args.ports.split(",")]
    if args.timeout is not None:
        overrides["timeout"] = args.timeout
    if args.concurrency is not None:
        overrides["concurrency"] = args.concurrency
    if args.use_nmap:
        overrides["use_nmap"] = True
    if args.skip_passive:
        overrides["skip_passive"] = True
    if args.internal_resolver:
        overrides["internal_resolver"] = args.internal_resolver
    if args.json_output:
        overrides["json_output"] = True
    if args.csv_output:
        overrides["csv_output"] = True
    if args.output_file:
        overrides["output_file"] = args.output_file
    if args.verbose:
        overrides["verbose"] = True
    if args.quiet:
        overrides["quiet"] = True

    # Load custom wordlist
    subdomain_wordlist = None
    if args.wordlist:
        wl_path = Path(args.wordlist)
        if wl_path.exists():
            subdomain_wordlist = [
                line.strip()
                for line in wl_path.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            ]
            overrides["subdomain_wordlist"] = subdomain_wordlist

    config_path = Path(args.config) if args.config else None
    config = load_config(config_path=config_path, cli_overrides=overrides)

    return config, domains


async def _run(config: Config, domains: list[str]) -> int:
    """Run the scan and return the appropriate exit code."""
    from hostprobe.output import _supports_color
    use_color = _supports_color() and not config.json_output

    reports = []

    if len(domains) == 1:
        # Single domain mode
        progress = TerminalProgress(domains[0], use_color, config.quiet)
        if not config.quiet and not config.json_output:
            sys.stderr.write(f"\n  Scanning {domains[0]}...\n")
            sys.stderr.flush()
        report = await analyze_domain(domains[0], config, progress)
        reports.append(report)
    else:
        # Batch mode
        batch_progress = BatchProgress(len(domains), use_color, config.quiet)
        for domain in domains:
            progress = batch_progress.start_domain(domain)
            report = await analyze_domain(domain, config, progress)
            reports.append(report)

    # Output
    if config.csv_output:
        sys.stdout.write(format_csv(reports))
    elif config.json_output:
        if len(reports) == 1:
            sys.stdout.write(format_json(reports[0]) + "\n")
        else:
            sys.stdout.write(format_json(reports) + "\n")
    elif config.quiet:
        for report in reports:
            sys.stdout.write(format_verdict_line(report, use_color) + "\n")
    else:
        for report in reports:
            sys.stdout.write(format_terminal(report, use_color) + "\n")

    # Write to file if requested
    if config.output_file:
        output_path = Path(config.output_file)
        if config.csv_output:
            output_path.write_text(format_csv(reports))
        elif len(reports) == 1:
            output_path.write_text(format_json(reports[0]) + "\n")
        else:
            output_path.write_text(format_json(reports) + "\n")
        if not config.quiet:
            sys.stderr.write(f"  Results written to {config.output_file}\n")

    # Exit code: for batch mode, use the "most alive" verdict
    if len(reports) == 1:
        return reports[0].verdict.exit_code
    else:
        return min(r.verdict.exit_code for r in reports)


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    try:
        config, domains = _parse_args(argv)
    except SystemExit:
        raise

    setup_logging(config.verbose)

    try:
        exit_code = asyncio.run(_run(config, domains))
    except KeyboardInterrupt:
        sys.stderr.write("\n  Interrupted.\n")
        sys.exit(130)
    except Exception as exc:
        sys.stderr.write(f"\n  Error: {exc}\n")
        if config.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        sys.exit(RUNTIME_ERROR_EXIT)

    sys.exit(exit_code)
