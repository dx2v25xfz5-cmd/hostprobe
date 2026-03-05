"""Configuration loading: CLI args → env vars → config file → defaults."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
DEFAULT_PORTS = [443, 80]
DEFAULT_TIMEOUT = 5.0
DEFAULT_CONCURRENCY = 20
DEFAULT_RETRIES = 3
DEFAULT_CONFIG_PATH = Path.home() / ".hostprobe.toml"

DEFAULT_SUBDOMAINS = [
    "www", "api", "dev", "stage", "staging", "mail", "vpn", "portal",
    "admin", "ftp", "webmail", "remote", "ns1", "ns2", "cdn", "app",
    "test", "beta", "internal", "mx", "smtp",
]


@dataclass
class Config:
    """Merged configuration for a hostprobe run."""

    # DNS
    resolvers: list[str] = field(default_factory=lambda: list(DEFAULT_RESOLVERS))
    dns_timeout: float = DEFAULT_TIMEOUT
    use_doh: bool = False               # DNS-over-HTTPS

    # Ports
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))

    # Subdomains
    subdomain_wordlist: list[str] = field(default_factory=lambda: list(DEFAULT_SUBDOMAINS))

    # Concurrency / retry / rate-limiting
    concurrency: int = DEFAULT_CONCURRENCY
    retries: int = DEFAULT_RETRIES
    rate_limit: float = 0.0             # requests/sec, 0 = unlimited

    # Network
    proxy: str | None = None            # HTTP/SOCKS5 proxy URL
    timeout: float = DEFAULT_TIMEOUT

    # API keys
    securitytrails_api_key: str | None = None
    virustotal_api_key: str | None = None
    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None

    # Optional flags
    use_nmap: bool = False
    internal_resolver: str | None = None
    skip_passive: bool = False
    verbose: bool = False
    quiet: bool = False

    # Output
    json_output: bool = False
    csv_output: bool = False
    html_output: bool = False
    output_file: str | None = None

    # Checkpoint / resume
    checkpoint_file: str | None = None

    # SQLite storage
    db_path: str | None = None
    client: str | None = None


def load_config(
    config_path: Path | None = None,
    cli_overrides: dict | None = None,
) -> Config:
    """Build a Config by merging file → env → CLI (highest priority wins)."""
    cfg = Config()

    # --- Layer 1: config file ---
    path = config_path or DEFAULT_CONFIG_PATH
    if path.exists() and tomllib is not None:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)

        dns_sec = data.get("dns", {})
        if "resolvers" in dns_sec:
            cfg.resolvers = dns_sec["resolvers"]
        if "timeout" in dns_sec:
            cfg.dns_timeout = float(dns_sec["timeout"])
            cfg.timeout = cfg.dns_timeout

        ports_sec = data.get("ports", {})
        if "default" in ports_sec:
            cfg.ports = [int(p) for p in ports_sec["default"]]

        sub_sec = data.get("subdomains", {})
        if "wordlist_path" in sub_sec:
            wl_path = Path(sub_sec["wordlist_path"]).expanduser()
            if wl_path.exists():
                cfg.subdomain_wordlist = [
                    line.strip() for line in wl_path.read_text().splitlines()
                    if line.strip() and not line.startswith("#")
                ]

        scan_sec = data.get("scan", {})
        if "concurrency" in scan_sec:
            cfg.concurrency = int(scan_sec["concurrency"])
        if "retries" in scan_sec:
            cfg.retries = int(scan_sec["retries"])

        keys_sec = data.get("api_keys", {})
        if "securitytrails" in keys_sec:
            cfg.securitytrails_api_key = keys_sec["securitytrails"]
        if "virustotal" in keys_sec:
            cfg.virustotal_api_key = keys_sec["virustotal"]
        if "shodan" in keys_sec:
            cfg.shodan_api_key = keys_sec["shodan"]
        if "censys_id" in keys_sec:
            cfg.censys_api_id = keys_sec["censys_id"]
        if "censys_secret" in keys_sec:
            cfg.censys_api_secret = keys_sec["censys_secret"]

        storage_sec = data.get("storage", {})
        if "db_path" in storage_sec:
            cfg.db_path = storage_sec["db_path"]
        if "client" in storage_sec:
            cfg.client = storage_sec["client"]

    # --- Layer 2: environment variables ---
    if env_st := os.environ.get("SECURITYTRAILS_API_KEY"):
        cfg.securitytrails_api_key = env_st
    if env_vt := os.environ.get("VIRUSTOTAL_API_KEY"):
        cfg.virustotal_api_key = env_vt
    if env_sh := os.environ.get("SHODAN_API_KEY"):
        cfg.shodan_api_key = env_sh
    if env_ci := os.environ.get("CENSYS_API_ID"):
        cfg.censys_api_id = env_ci
    if env_cs := os.environ.get("CENSYS_API_SECRET"):
        cfg.censys_api_secret = env_cs
    if env_proxy := os.environ.get("HOSTPROBE_PROXY"):
        cfg.proxy = env_proxy
    if env_db := os.environ.get("HOSTPROBE_DB"):
        cfg.db_path = env_db
    if env_client := os.environ.get("HOSTPROBE_CLIENT"):
        cfg.client = env_client

    # --- Layer 3: CLI overrides (highest priority) ---
    if cli_overrides:
        for key, value in cli_overrides.items():
            if value is not None and hasattr(cfg, key):
                setattr(cfg, key, value)

    return cfg
