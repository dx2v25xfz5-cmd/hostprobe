"""WAF / firewall detection via HTTP response analysis."""

from __future__ import annotations

import logging
import re
from typing import Optional

from hostprobe.models import HTTPResult, WAFResult

logger = logging.getLogger("hostprobe")

# ---------------------------------------------------------------------------
# WAF signature database
# ---------------------------------------------------------------------------

# Map of WAF provider → (header checks, response body patterns)
_WAF_SIGNATURES: dict[str, dict] = {
    "Cloudflare": {
        "headers": {
            "Server": re.compile(r"cloudflare", re.I),
            "CF-RAY": re.compile(r".+"),
            "CF-Cache-Status": re.compile(r".+"),
        },
        "status_codes": {403, 503, 520, 521, 522, 523, 524, 525, 526},
        "body_patterns": [
            re.compile(r"Attention Required.*Cloudflare", re.I),
            re.compile(r"cf-error-details", re.I),
            re.compile(r"ray\s*ID", re.I),
        ],
    },
    "AWS WAF": {
        "headers": {
            "x-amzn-waf-action": re.compile(r".+"),
            "x-amzn-RequestId": re.compile(r".+"),
        },
        "status_codes": {403},
        "body_patterns": [
            re.compile(r"<html>.*Request blocked.*</html>", re.I | re.S),
        ],
    },
    "AWS CloudFront": {
        "headers": {
            "X-Amz-Cf-Id": re.compile(r".+"),
            "X-Amz-Cf-Pop": re.compile(r".+"),
            "Via": re.compile(r"cloudfront", re.I),
        },
        "status_codes": set(),
        "body_patterns": [],
    },
    "Akamai": {
        "headers": {
            "X-Akamai-Transformed": re.compile(r".+"),
            "Server": re.compile(r"AkamaiGHost", re.I),
        },
        "status_codes": {403},
        "body_patterns": [
            re.compile(r"Reference.*akamai", re.I),
        ],
    },
    "Imperva / Incapsula": {
        "headers": {
            "X-CDN": re.compile(r"Imperva|Incapsula", re.I),
            "X-Iinfo": re.compile(r".+"),
        },
        "status_codes": {403},
        "body_patterns": [
            re.compile(r"Incapsula incident ID", re.I),
            re.compile(r"_Incapsula_Resource", re.I),
        ],
    },
    "Sucuri": {
        "headers": {
            "X-Sucuri-ID": re.compile(r".+"),
            "Server": re.compile(r"Sucuri", re.I),
        },
        "status_codes": {403},
        "body_patterns": [
            re.compile(r"Sucuri WebSite Firewall", re.I),
            re.compile(r"Access Denied.*Sucuri", re.I),
        ],
    },
    "F5 BIG-IP ASM": {
        "headers": {
            "Server": re.compile(r"BIG-?IP|F5", re.I),
            "X-WA-Info": re.compile(r".+"),
        },
        "status_codes": {403},
        "body_patterns": [
            re.compile(r"The requested URL was rejected", re.I),
        ],
    },
    "ModSecurity": {
        "headers": {
            "Server": re.compile(r"mod_security|NOYB", re.I),
        },
        "status_codes": {403, 406},
        "body_patterns": [
            re.compile(r"ModSecurity|Mod_Security", re.I),
            re.compile(r"Not Acceptable.*security module", re.I),
        ],
    },
    "Azure Front Door / WAF": {
        "headers": {
            "X-Azure-Ref": re.compile(r".+"),
            "X-FD-HealthProbe": re.compile(r".+"),
        },
        "status_codes": {403},
        "body_patterns": [],
    },
    "Google Cloud Armor": {
        "headers": {},
        "status_codes": {403},
        "body_patterns": [
            re.compile(r"Google Cloud Armor", re.I),
        ],
    },
    "Fastly": {
        "headers": {
            "X-Served-By": re.compile(r"cache-", re.I),
            "Via": re.compile(r"varnish", re.I),
            "X-Fastly-Request-ID": re.compile(r".+"),
        },
        "status_codes": set(),
        "body_patterns": [],
    },
    "StackPath": {
        "headers": {
            "X-SP-URL": re.compile(r".+"),
            "X-SP-WQ": re.compile(r".+"),
        },
        "status_codes": {403},
        "body_patterns": [
            re.compile(r"StackPath", re.I),
        ],
    },
    "DDoS-Guard": {
        "headers": {
            "Server": re.compile(r"ddos-guard", re.I),
        },
        "status_codes": {403},
        "body_patterns": [
            re.compile(r"DDoS protection by DDos-Guard", re.I),
        ],
    },
}


def detect_waf(
    http_result: HTTPResult | None,
    response_body: str = "",
) -> WAFResult:
    """Detect WAF/CDN security products from HTTP response.

    Parameters
    ----------
    http_result:
        The HTTP probe result containing status code and headers.
    response_body:
        Optional HTTP response body text for deeper analysis.

    Returns
    -------
    WAFResult
        Detection result with provider name and evidence.
    """
    result = WAFResult()

    if not http_result or not http_result.headers:
        return result

    headers = http_result.headers
    status = http_result.status_code

    for waf_name, sig in _WAF_SIGNATURES.items():
        evidence: list[str] = []

        # Check headers
        for header_name, pattern in sig.get("headers", {}).items():
            header_value = headers.get(header_name, "")
            if header_value and pattern.search(header_value):
                evidence.append(f"header {header_name}: {header_value}")

        # Check status code (only if combined with at least some header evidence)
        blocking = False
        if status and status in sig.get("status_codes", set()):
            if evidence:
                evidence.append(f"status {status} (known block code)")
                blocking = True

        # Check body patterns
        for body_pat in sig.get("body_patterns", []):
            if response_body and body_pat.search(response_body):
                evidence.append(f"body match: {body_pat.pattern[:60]}")
                blocking = True

        # Require at least one piece of evidence
        if evidence:
            result.detected = True
            result.provider = waf_name
            result.evidence = evidence
            result.is_blocking = blocking
            logger.info("WAF detected: %s (%d evidence items)", waf_name, len(evidence))
            return result

    return result
