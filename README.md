# hostprobe

Host discovery & non-resolving domain assessment tool.

`hostprobe` walks a structured decision tree to determine:

1. Whether a host is actually alive
2. Whether a domain truly has no backing infrastructure
3. Whether DNS failure is masking an active system
4. When further testing is justified

> **⚖️ Use only on systems you own or are explicitly authorized to assess.**

## Installation

```bash
# From source
cd hostprobe
pip install -e .

# Or with dev dependencies
pip install -e ".[dev]"
```

### Prerequisites

- **Python ≥ 3.11**
- **ping** — usually pre-installed (used for ICMP probes)
- **nmap** — optional, only needed with `--nmap` flag (SYN scans require root)

## Quick Start

```bash
# Single domain
hostprobe example.com

# JSON output
hostprobe --json example.com

# Batch mode
hostprobe -f domains.txt

# Quiet mode (verdict line only)
hostprobe -q example.com

# Write JSON to file
hostprobe -o results.json example.com

# Custom ports + verbose logging
hostprobe --ports 443,80,8080,8443 -v example.com

# Use nmap for SYN scans (requires root)
sudo hostprobe --nmap example.com

# Skip passive recon (faster, no external API calls)
hostprobe --skip-passive example.com

# Test with internal DNS resolver (split-horizon)
hostprobe --internal-resolver 10.0.0.53 internal.corp.com
```

## Decision Tree

The tool implements a multi-phase automatic workflow:

```
Phase 1 — DNS + WHOIS + DNSSEC + CNAME chain (concurrent)
    ├── Domain resolves? → Phase 2 (host discovery)
    ├── NXDOMAIN? → Check subdomains + CT logs + passive DNS
    │   ├── Subdomains resolve → pivot and probe them
    │   ├── CT/passive signals → investigate decommission
    │   └── Nothing found → LIKELY DEAD (stop)
    ├── SERVFAIL? → DNSSEC diagnostics → INVESTIGATE
    └── NOERROR no A? → Check AAAA/MX/TXT → PARTIAL

Phase 2 — Host Discovery (layered)
    ├── ICMP ping
    ├── TCP port probes (443, 80, ...)
    ├── TLS handshake + certificate analysis
    ├── HTTP HEAD request
    ├── SMTP validation (if MX exists)
    └── Banner grabs

Phase 3 — Edge Cases
    ├── Wildcard DNS detection
    ├── CDN detection (Cloudflare, Akamai, CloudFront, etc.)
    ├── Cloud artifact scanning (AWS, Azure, GCP)
    ├── Dangling CNAME detection (subdomain takeover risk)
    ├── IPv6 connectivity
    └── Split-horizon DNS comparison

Phase 4 — Decommission Analysis
    └── Cross-reference passive DNS + CT + WHOIS + IP probes

Phase 5 — Verdict
    ALIVE | LIKELY_DEAD | FILTERED | PARTIAL | INVESTIGATE | RECENTLY_DECOMMISSIONED
```

## Verdicts

| Verdict | Meaning | Exit Code |
|---------|---------|-----------|
| `ALIVE` | Host responds (TCP, TLS, HTTP, or SMTP) | 0 |
| `LIKELY_DEAD` | No DNS, no subdomains, no historical evidence | 1 |
| `INVESTIGATE` | SERVFAIL, DNSSEC issues, or ambiguous signals | 2 |
| `PARTIAL` | Domain exists (MX/TXT) but no reachable host | 3 |
| `FILTERED` | All ports timeout (firewall or dead) | 4 |
| `RECENTLY_DECOMMISSIONED` | DNS removed but infrastructure likely still running | 5 |
| *(error)* | Runtime error | 10 |

## Configuration

Create `~/.hostprobe.toml` for persistent settings:

```toml
[dns]
resolvers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
timeout = 5

[ports]
default = [443, 80, 8080]

[subdomains]
wordlist_path = "~/wordlists/subdomains.txt"

[scan]
concurrency = 20
retries = 3

[api_keys]
securitytrails = "your-api-key"
virustotal = "your-api-key"
```

API keys can also be set via environment variables:
```bash
export SECURITYTRAILS_API_KEY="..."
export VIRUSTOTAL_API_KEY="..."
```

Priority: CLI flags > env vars > config file > defaults.

## CLI Reference

| Flag | Description |
|------|-------------|
| `<domain>` | Single domain to analyze |
| `-f, --file` | File with one domain per line |
| `--json` | JSON-only output |
| `-o, --output` | Write JSON to file |
| `--config` | Path to config file (default: `~/.hostprobe.toml`) |
| `--nmap` | Use nmap SYN scan (requires root + nmap) |
| `--internal-resolver` | IP of internal DNS server |
| `--timeout` | Per-probe timeout in seconds (default: 5) |
| `--ports` | Comma-separated port list (default: 443,80) |
| `--wordlist` | Custom subdomain wordlist file |
| `--skip-passive` | Skip CT log / passive DNS lookups |
| `--concurrency` | Max concurrent operations (default: 20) |
| `-v, --verbose` | Debug logging to stderr |
| `-q, --quiet` | Verdict line only |

## Architecture

```
hostprobe/
├── cli.py               # Argument parsing + exit codes
├── config.py            # Config file + env var + CLI merge
├── runner.py            # Decision tree orchestrator (async)
├── dns_checks.py        # DNS classification, records, CNAME, DNSSEC
├── subdomain_checks.py  # Subdomain enumeration
├── passive_recon.py     # CT logs (crt.sh), SecurityTrails, VirusTotal
├── whois_check.py       # Domain registration check
├── host_discovery.py    # ICMP, TCP, TLS, SMTP, HTTP, banners
├── edge_cases.py        # Wildcard, CDN, split-horizon, IPv6
├── cloud_checks.py      # AWS/Azure/GCP artifacts, dangling CNAMEs
├── decommission.py      # Recently-decommissioned correlation
├── models.py            # Dataclasses and enums
├── output.py            # JSON + ANSI terminal formatting
└── utils.py             # Retry, subprocess, concurrency helpers
```

All I/O operations are async (`asyncio`). DNS queries, port probes, HTTP requests,
and CT log lookups run concurrently within and across phases.

## License

MIT
