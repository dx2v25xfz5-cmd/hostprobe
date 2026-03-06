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
    format_html,
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
        "--html",
        action="store_true",
        dest="html_output",
        help="Output self-contained HTML report",
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
    scan_group.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        dest="rate_limit",
        help="Max requests per second (0 = unlimited, default: 0)",
    )
    scan_group.add_argument(
        "--proxy",
        type=str,
        default=None,
        help="HTTP/SOCKS5 proxy URL (e.g. socks5://127.0.0.1:9050)",
    )
    scan_group.add_argument(
        "--doh",
        action="store_true",
        dest="use_doh",
        help="Use DNS-over-HTTPS (Cloudflare) instead of plain DNS",
    )
    scan_group.add_argument(
        "--shodan-key",
        type=str,
        default=None,
        dest="shodan_api_key",
        help="Shodan API key for passive port/service data",
    )
    scan_group.add_argument(
        "--censys-id",
        type=str,
        default=None,
        dest="censys_api_id",
        help="Censys API ID",
    )
    scan_group.add_argument(
        "--censys-secret",
        type=str,
        default=None,
        dest="censys_api_secret",
        help="Censys API secret",
    )
    scan_group.add_argument(
        "--checkpoint",
        type=str,
        default=None,
        dest="checkpoint_file",
        help="Save/resume batch progress to this file",
    )

    # Storage
    storage_group = parser.add_argument_group("storage")
    storage_group.add_argument(
        "--db",
        type=str,
        default=None,
        dest="db_path",
        help="SQLite database path for persistent storage",
    )
    storage_group.add_argument(
        "--client",
        type=str,
        default=None,
        dest="client",
        help="Client/project name for multi-tenant DB storage (required with --db)",
    )

    return parser


def _parse_args(argv: list[str] | None = None) -> tuple[Config, list[str], dict[str, str]]:
    """Parse CLI args and return (Config, list_of_domains, domain_clients_map)."""
    parser = build_parser()

    # Shell completion (if argcomplete is installed)
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args(argv)

    if not args.domain and not args.file:
        parser.error("either a domain argument or -f/--file is required")

    # Collect domains
    domains: list[str] = []
    # Per-domain client mapping (populated from CSV files)
    domain_clients: dict[str, str] = {}

    if args.domain:
        domains.append(args.domain.strip().lower())
    if args.file:
        path = Path(args.file)
        if not path.exists():
            parser.error(f"file not found: {args.file}")
        if path.suffix.lower() == ".csv":
            # CSV file — look for 'domain' and optional 'client' columns
            import csv as _csv
            with open(path, newline="") as fh:
                reader = _csv.DictReader(fh)
                if not reader.fieldnames or "domain" not in [f.lower().strip() for f in reader.fieldnames]:
                    parser.error("CSV file must have a 'domain' column")
                # Normalise headers
                domain_col = next(f for f in reader.fieldnames if f.lower().strip() == "domain")
                client_col = next(
                    (f for f in reader.fieldnames if f.lower().strip() == "client"), None
                )
                for row in reader:
                    d = row[domain_col].strip().lower()
                    if d and not d.startswith("#"):
                        domains.append(d)
                        if client_col and row.get(client_col, "").strip():
                            domain_clients[d] = row[client_col].strip()
        else:
            # Plain text — one domain per line
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
    if args.html_output:
        overrides["html_output"] = True
    if args.rate_limit is not None:
        overrides["rate_limit"] = args.rate_limit
    if args.proxy:
        overrides["proxy"] = args.proxy
    if args.use_doh:
        overrides["use_doh"] = True
    if args.shodan_api_key:
        overrides["shodan_api_key"] = args.shodan_api_key
    if args.censys_api_id:
        overrides["censys_api_id"] = args.censys_api_id
    if args.censys_api_secret:
        overrides["censys_api_secret"] = args.censys_api_secret
    if args.checkpoint_file:
        overrides["checkpoint_file"] = args.checkpoint_file
    if args.db_path:
        overrides["db_path"] = args.db_path
    if args.client:
        overrides["client"] = args.client
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

    # Validate: --db requires --client (unless CSV provides per-row clients)
    if config.db_path and not config.client and not domain_clients:
        parser.error("--client is required when using --db (or use a CSV file with a 'client' column)")

    return config, domains, domain_clients


async def _run(config: Config, domains: list[str], domain_clients: dict[str, str] | None = None) -> int:
    """Run the scan and return the appropriate exit code."""
    if domain_clients is None:
        domain_clients = {}
    from hostprobe.output import _supports_color
    use_color = _supports_color() and not config.json_output

    # Initialise rate limiter
    if config.rate_limit and config.rate_limit > 0:
        from hostprobe.utils import init_rate_limiter
        init_rate_limiter(config.rate_limit)

    # Load checkpoint (resume mode)
    completed_domains: set[str] = set()
    if config.checkpoint_file:
        completed_domains = _load_checkpoint(config.checkpoint_file)
        if completed_domains:
            domains = [d for d in domains if d not in completed_domains]
            if not config.quiet:
                sys.stderr.write(f"  Resuming — {len(completed_domains)} domains already done\n")

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
        for i, domain in enumerate(domains, 1):
            progress = batch_progress.start_domain(domain)
            report = await analyze_domain(domain, config, progress)
            reports.append(report)
            # Save checkpoint after each domain
            if config.checkpoint_file:
                _save_checkpoint(config.checkpoint_file, completed_domains | {r.domain for r in reports})
        batch_progress.summary()

    # Output
    if config.html_output:
        sys.stdout.write(format_html(reports))
    elif config.csv_output:
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

    # Save to SQLite if requested
    if config.db_path:
        from hostprobe.storage import HostprobeDB
        with HostprobeDB(config.db_path) as db:
            for report in reports:
                # Client resolution: per-domain (CSV) > --client flag > config
                client_name = domain_clients.get(report.domain) or config.client
                if client_name:
                    db.save_report(client_name, report)
            if not config.quiet:
                client_label = config.client or "per-CSV"
                sys.stderr.write(
                    f"  {len(reports)} result(s) saved to {config.db_path}"
                    f" (client: {client_label})\n"
                )

    # Write to file if requested
    if config.output_file:
        output_path = Path(config.output_file)
        if config.html_output:
            output_path.write_text(format_html(reports))
        elif config.csv_output:
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


# ---------------------------------------------------------------------------
# Checkpoint helpers
# ---------------------------------------------------------------------------

def _load_checkpoint(path: str) -> set[str]:
    """Load completed domains from a checkpoint file."""
    import json
    try:
        data = Path(path).read_text()
        return set(json.loads(data).get("completed", []))
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return set()


def _save_checkpoint(path: str, completed: set[str]) -> None:
    """Save completed domains to a checkpoint file."""
    import json
    Path(path).write_text(json.dumps({"completed": sorted(completed)}))


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    # Route to `db` subcommand if first arg is "db"
    args = argv if argv is not None else sys.argv[1:]
    if args and args[0] == "db":
        from hostprobe.db_cli import db_main
        db_main(args[1:])
        return

    try:
        config, domains, domain_clients = _parse_args(argv)
    except SystemExit:
        raise

    setup_logging(config.verbose)

    try:
        exit_code = asyncio.run(_run(config, domains, domain_clients))
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
