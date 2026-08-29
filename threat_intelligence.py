"""
threat_intelligence.py — optional, best-effort external checks.

Both VirusTotal and Google Safe Browsing are treated strictly as
*supplementary* signals:

- If no API key is configured, these functions return a clear
  "not_configured" status and the rest of the app proceeds using only
  detector.py's local rules.
- If a request errors, times out, or the service is unavailable, the same
  graceful fallback happens -- this module never raises an exception out
  to app.py.
- This module never submits credentials, personal data, or file payloads
  anywhere. It only ever sends the URL string itself for lookup.
- This module does not crawl, exploit, or interact with the target
  website in any way; it only queries third-party reputation APIs about
  the URL.
"""

import base64
import time
from dataclasses import dataclass
from typing import Optional

import requests

import config


@dataclass
class ThreatIntelResult:
    source: str                # "VirusTotal" | "Google Safe Browsing"
    status: str                 # "not_configured" | "ok" | "error" | "timeout"
    is_flagged: Optional[bool]  # True/False if known, None if not determined
    detail: str                 # human-readable summary
    raw: Optional[dict] = None


def _vt_headers() -> dict:
    return {"x-apikey": config.VIRUSTOTAL_API_KEY}


def check_virustotal(url: str) -> ThreatIntelResult:
    """Look up a URL's existing VirusTotal analysis (does not force a new
    scan, to avoid submitting URLs to a third party without clear intent
    and to keep response times short for a live demo).
    """
    if not config.VIRUSTOTAL_API_KEY:
        return ThreatIntelResult(
            "VirusTotal", "not_configured", None,
            "VirusTotal API key not configured -- skipped.",
        )

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(
            endpoint,
            headers=_vt_headers(),
            timeout=config.THREAT_INTEL_TIMEOUT_SECONDS,
        )
        if response.status_code == 404:
            return ThreatIntelResult(
                "VirusTotal", "ok", None,
                "This URL has not been previously analyzed by VirusTotal.",
            )
        response.raise_for_status()
        data = response.json()
        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        flagged = (malicious + suspicious) > 0
        detail = (
            f"{malicious} vendor(s) flagged this URL as malicious and "
            f"{suspicious} as suspicious, out of the vendors VirusTotal "
            "polls."
        )
        return ThreatIntelResult("VirusTotal", "ok", flagged, detail, data)

    except requests.exceptions.Timeout:
        return ThreatIntelResult(
            "VirusTotal", "timeout", None,
            "VirusTotal did not respond in time -- continuing with local "
            "detection only.",
        )
    except requests.exceptions.RequestException as exc:
        return ThreatIntelResult(
            "VirusTotal", "error", None,
            f"Could not reach VirusTotal ({exc.__class__.__name__}) -- "
            "continuing with local detection only.",
        )
    except (ValueError, KeyError) as exc:
        return ThreatIntelResult(
            "VirusTotal", "error", None,
            f"Unexpected VirusTotal response format ({exc.__class__.__name__}) "
            "-- continuing with local detection only.",
        )


def check_google_safe_browsing(url: str) -> ThreatIntelResult:
    if not config.GOOGLE_SAFE_BROWSING_API_KEY:
        return ThreatIntelResult(
            "Google Safe Browsing", "not_configured", None,
            "Google Safe Browsing API key not configured -- skipped.",
        )

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={config.GOOGLE_SAFE_BROWSING_API_KEY}"
    )
    payload = {
        "client": {"clientId": "link-suraksha", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            endpoint, json=payload, timeout=config.THREAT_INTEL_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        data = response.json()
        matches = data.get("matches", [])
        flagged = len(matches) > 0
        if flagged:
            threat_types = ", ".join(sorted({m.get("threatType", "?") for m in matches}))
            detail = f"Google Safe Browsing flagged this URL for: {threat_types}."
        else:
            detail = "Google Safe Browsing has no record of this URL as unsafe."
        return ThreatIntelResult("Google Safe Browsing", "ok", flagged, detail, data)

    except requests.exceptions.Timeout:
        return ThreatIntelResult(
            "Google Safe Browsing", "timeout", None,
            "Google Safe Browsing did not respond in time -- continuing "
            "with local detection only.",
        )
    except requests.exceptions.RequestException as exc:
        return ThreatIntelResult(
            "Google Safe Browsing", "error", None,
            f"Could not reach Google Safe Browsing ({exc.__class__.__name__}) "
            "-- continuing with local detection only.",
        )
    except ValueError as exc:
        return ThreatIntelResult(
            "Google Safe Browsing", "error", None,
            f"Unexpected Google Safe Browsing response format "
            f"({exc.__class__.__name__}) -- continuing with local "
            "detection only.",
        )


def run_all_checks(url: str) -> list:
    """Run whichever threat-intel checks are configured. Always returns a
    list (possibly of "not_configured" results) and never raises.
    """
    results = []
    start = time.time()
    results.append(check_virustotal(url))
    results.append(check_google_safe_browsing(url))
    elapsed = time.time() - start
    return results, elapsed
