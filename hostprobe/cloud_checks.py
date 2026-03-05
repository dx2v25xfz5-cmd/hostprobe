"""Cloud-specific artifact detection and dangling CNAME identification."""

from __future__ import annotations

import logging

from hostprobe.models import SubdomainEntry

logger = logging.getLogger("hostprobe")

# ---------------------------------------------------------------------------
# Cloud CNAME / naming patterns
# ---------------------------------------------------------------------------

CLOUD_PATTERNS: dict[str, list[str]] = {
    "AWS": [
        ".amazonaws.com",
        ".elasticbeanstalk.com",
        ".cloudfront.net",
        ".s3.amazonaws.com",
        ".s3-website",
        ".elb.amazonaws.com",
        ".execute-api.",
        ".lambda-url.",
    ],
    "Azure": [
        ".azurewebsites.net",
        ".azurefd.net",
        ".blob.core.windows.net",
        ".trafficmanager.net",
        ".azure-api.net",
        ".azurecontainer.io",
        ".azurecr.io",
        ".database.windows.net",
        ".vault.azure.net",
        ".servicebus.windows.net",
    ],
    "GCP": [
        ".run.app",
        ".cloudfunctions.net",
        ".appspot.com",
        ".googleapis.com",
        ".firebaseapp.com",
        ".web.app",
    ],
}

# Services known for subdomain takeover via dangling CNAME
TAKEOVER_TARGETS = [
    # (CNAME pattern, service, indicator of vulnerability)
    (".s3.amazonaws.com", "AWS S3", "NoSuchBucket"),
    (".elasticbeanstalk.com", "AWS Elastic Beanstalk", "NXDOMAIN"),
    (".azurewebsites.net", "Azure App Service", "NXDOMAIN"),
    (".cloudapp.azure.com", "Azure VM", "NXDOMAIN"),
    (".trafficmanager.net", "Azure Traffic Manager", "NXDOMAIN"),
    (".herokuapp.com", "Heroku", "NXDOMAIN"),
    (".github.io", "GitHub Pages", "NXDOMAIN"),
    (".firebaseapp.com", "Firebase", "NXDOMAIN"),
    (".web.app", "Firebase Hosting", "NXDOMAIN"),
    (".pantheonsite.io", "Pantheon", "NXDOMAIN"),
    (".ghost.io", "Ghost", "NXDOMAIN"),
    (".surge.sh", "Surge", "NXDOMAIN"),
    (".bitbucket.io", "Bitbucket", "NXDOMAIN"),
]


def detect_cloud_artifacts(
    cname_chains: dict[str, list[str]] | None = None,
    subdomain_results: list[SubdomainEntry] | None = None,
) -> tuple[str | None, list[str]]:
    """Scan CNAME targets and subdomain data for cloud provider indicators.

    Returns:
        (cloud_provider, list_of_artifact_descriptions)
    """
    artifacts: list[str] = []
    providers: set[str] = set()

    # Collect all CNAME targets
    all_cnames: list[str] = []
    if cname_chains:
        for chain in cname_chains.values():
            all_cnames.extend(chain)
    if subdomain_results:
        for sub in subdomain_results:
            if sub.cname_target:
                all_cnames.append(sub.cname_target)

    for cname in all_cnames:
        cname_lower = cname.lower()
        for provider, patterns in CLOUD_PATTERNS.items():
            for pattern in patterns:
                if pattern in cname_lower:
                    providers.add(provider)
                    artifacts.append(f"{provider}: CNAME points to {cname}")
                    break

    # Determine primary provider
    primary = None
    if len(providers) == 1:
        primary = providers.pop()
    elif providers:
        primary = ", ".join(sorted(providers))

    return (primary, artifacts)


def detect_dangling_cnames(
    subdomain_results: list[SubdomainEntry] | None = None,
) -> list[str]:
    """Find subdomains with CNAME records whose targets don't resolve.

    A dangling CNAME (CNAME exists but target is NXDOMAIN) indicates a
    potential subdomain takeover vulnerability.

    Returns list of affected FQDNs with descriptions.
    """
    dangling: list[str] = []

    if not subdomain_results:
        return dangling

    for sub in subdomain_results:
        if sub.cname_target and not sub.resolved:
            # CNAME exists but the subdomain itself didn't yield an IP
            # → the CNAME target likely doesn't resolve
            desc = f"{sub.fqdn} → CNAME {sub.cname_target} (target does not resolve)"

            # Check if it matches a known takeover-vulnerable service
            for pattern, service, _ in TAKEOVER_TARGETS:
                if pattern in sub.cname_target.lower():
                    desc += f" [potential {service} takeover]"
                    break

            dangling.append(desc)
            logger.warning("Dangling CNAME: %s", desc)

    return dangling
