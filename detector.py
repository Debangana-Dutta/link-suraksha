"""
detector.py — Link Suraksha's local, explainable URL risk detector.

This module never makes a network call. It looks only at the structure of
the URL string itself and applies 15 independent, named rules. Each rule
that fires contributes a documented number of points (see config.py
RULE_WEIGHTS) to a raw score, which is then scaled to 0-100 and mapped to
a risk level using the thresholds in config.py.

Design principle: the detector must never claim a URL is *definitely*
safe. The SAFE branch always uses hedged language ("no obvious risk
detected by local checks"), because a purely structural, offline check
cannot prove a page's content or backend behaviour is safe.
"""

from dataclasses import dataclass, field
from typing import List

import config
import utils


@dataclass
class TriggeredRule:
    rule_id: str
    name: str
    explanation: str
    score_contribution: float


@dataclass
class DetectionResult:
    original_input: str
    normalized_url: str
    hostname: str
    is_valid: bool
    raw_score: float
    risk_score: float          # scaled 0-100
    risk_level: str            # "SAFE" | "SUSPICIOUS" | "DANGEROUS"
    triggered_rules: List[TriggeredRule] = field(default_factory=list)
    summary: str = ""

    @property
    def reasons(self) -> List[str]:
        """Short human-readable reasons, one per triggered rule."""
        return [f"{r.name}: {r.explanation}" for r in self.triggered_rules]


def _rule_ip_address_host(hostname: str) -> TriggeredRule | None:
    if utils.is_ip_address(hostname):
        return TriggeredRule(
            "ip_address_host",
            "IP address instead of domain",
            "The link uses a raw IP address rather than a normal domain name, "
            "which is a common way to hide the true identity of a website.",
            config.RULE_WEIGHTS["ip_address_host"],
        )
    return None


def _rule_suspicious_length(url: str) -> TriggeredRule | None:
    from urllib.parse import urlparse
    path = urlparse(url).path or ""
    if len(url) > config.LONG_URL_LENGTH_THRESHOLD or len(path) > config.LONG_PATH_LENGTH_THRESHOLD:
        return TriggeredRule(
            "suspicious_length",
            "Suspicious URL length",
            f"The link is unusually long ({len(url)} characters), which is "
            "sometimes used to hide the real destination or pack in extra "
            "tracking/redirect parameters.",
            config.RULE_WEIGHTS["suspicious_length"],
        )
    return None


def _rule_excessive_subdomains(hostname: str) -> TriggeredRule | None:
    count = utils.count_subdomain_labels(hostname)
    if count > config.MAX_SUBDOMAIN_LABELS:
        return TriggeredRule(
            "excessive_subdomains",
            "Excessive subdomains",
            f"The domain has an unusually deep subdomain chain ({count} extra "
            "levels), which can be used to make a fake address look official.",
            config.RULE_WEIGHTS["excessive_subdomains"],
        )
    return None


def _rule_excessive_hyphens(hostname: str) -> TriggeredRule | None:
    count = utils.count_hyphens(hostname)
    if count > config.MAX_HYPHENS_IN_HOST:
        return TriggeredRule(
            "excessive_hyphens",
            "Excessive hyphens",
            f"The domain contains an unusually high number of hyphens ({count}), "
            "a pattern often used to mimic a real brand name.",
            config.RULE_WEIGHTS["excessive_hyphens"],
        )
    return None


def _rule_suspicious_tld(hostname: str) -> TriggeredRule | None:
    if not hostname or utils.is_ip_address(hostname):
        return None
    tld = hostname.rsplit(".", 1)[-1]
    if tld in config.SUSPICIOUS_TLDS:
        return TriggeredRule(
            "suspicious_tld",
            "Suspicious top-level domain",
            f"The domain ends in '.{tld}', a top-level domain that is cheap "
            "to register in bulk and is disproportionately used for abuse. "
            "(Many legitimate sites also use it, so this alone is only a "
            "moderate signal.)",
            config.RULE_WEIGHTS["suspicious_tld"],
        )
    return None


def _rule_url_shortener(hostname: str) -> TriggeredRule | None:
    if hostname in config.URL_SHORTENERS:
        return TriggeredRule(
            "url_shortener",
            "URL shortener",
            "The link uses a URL-shortening service, which hides the real "
            "destination until you click. Shorteners are also used "
            "legitimately, so this alone is only a moderate signal.",
            config.RULE_WEIGHTS["url_shortener"],
        )
    return None


def _rule_suspicious_keywords(url: str) -> TriggeredRule | None:
    lowered = url.lower()
    hits = [kw for kw in config.SUSPICIOUS_KEYWORDS if kw in lowered]
    if hits:
        weight = min(config.RULE_WEIGHTS["suspicious_keywords"], 6 * len(hits))
        shown = ", ".join(sorted(set(hits))[:4])
        return TriggeredRule(
            "suspicious_keywords",
            "Suspicious keywords",
            f"The link text contains urgency/reward-style keywords ({shown}), "
            "commonly used in scam and phishing messages.",
            weight,
        )
    return None


def _rule_login_verification_language(url: str) -> TriggeredRule | None:
    lowered = url.lower()
    hits = [kw for kw in config.LOGIN_VERIFICATION_KEYWORDS if kw in lowered]
    if hits:
        weight = min(config.RULE_WEIGHTS["login_verification_language"], 6 * len(hits))
        shown = ", ".join(sorted(set(hits))[:4])
        return TriggeredRule(
            "login_verification_language",
            "Login / verification / KYC / payment language",
            f"The link references account/login/KYC/payment actions ({shown}). "
            "This is completely normal for real banking or e-commerce "
            "sites too, but combined with other signals it raises risk.",
            weight,
        )
    return None


def _rule_brand_impersonation(hostname: str) -> TriggeredRule | None:
    if not hostname:
        return None
    registrable = utils.get_registrable_domain(hostname)
    if registrable in config.OFFICIAL_BRAND_DOMAINS:
        return None  # this IS the brand's real domain -- do not flag it

    normalized_host = utils.normalize_for_brand_match(hostname)
    for brand in config.BRAND_TOKENS:
        if brand in normalized_host:
            return TriggeredRule(
                "brand_impersonation",
                "Possible brand impersonation",
                f"The domain contains the brand name/token '{brand}' but is "
                "not that brand's official website, a pattern typical of "
                "impersonation domains.",
                config.RULE_WEIGHTS["brand_impersonation"],
            )
    return None


def _rule_at_symbol(url: str) -> TriggeredRule | None:
    if utils.has_at_symbol(url):
        return TriggeredRule(
            "at_symbol",
            "'@' symbol in URL",
            "The link contains an '@' symbol before the path. Browsers "
            "ignore everything before '@', so this is a classic trick to "
            "make a fake destination look like a trusted one.",
            config.RULE_WEIGHTS["at_symbol"],
        )
    return None


def _rule_excessive_encoding(url: str) -> TriggeredRule | None:
    count = utils.percent_encoded_count(url)
    if count > config.MAX_PERCENT_ENCODED_CHARS:
        return TriggeredRule(
            "excessive_encoding",
            "Excessive URL encoding",
            f"The link has {count} percent-encoded characters, more than "
            "expected for a normal link. Heavy encoding is sometimes used "
            "to hide suspicious words or characters from a quick glance.",
            config.RULE_WEIGHTS["excessive_encoding"],
        )
    return None


def _rule_suspicious_query_params(url: str) -> TriggeredRule | None:
    names = set(utils.get_query_param_names(url))
    hits = names & config.SUSPICIOUS_QUERY_PARAM_NAMES
    if hits:
        shown = ", ".join(sorted(hits))
        return TriggeredRule(
            "suspicious_query_params",
            "Suspicious query parameters",
            f"The link's query string includes parameter name(s) ({shown}) "
            "sometimes seen in credential-harvesting or open-redirect links.",
            config.RULE_WEIGHTS["suspicious_query_params"],
        )
    return None


def _rule_punycode_idn(hostname: str) -> TriggeredRule | None:
    if utils.is_punycode(hostname):
        return TriggeredRule(
            "punycode_idn",
            "Punycode / IDN domain",
            "The domain uses punycode (an encoding for non-Latin "
            "characters), which is sometimes used to create look-alike "
            "domains with characters that resemble a trusted brand.",
            config.RULE_WEIGHTS["punycode_idn"],
        )
    return None


def _rule_suspicious_domain_structure(hostname: str) -> TriggeredRule | None:
    """Catches a few structural oddities not covered by the more specific
    rules above: a very high proportion of digits in the domain, or a
    registrable domain made almost entirely of digits/hyphens (looks
    machine-generated rather than a brand or word).
    """
    if not hostname or utils.is_ip_address(hostname):
        return None
    registrable = utils.get_registrable_domain(hostname)
    core = registrable.split(".")[0] if registrable else ""
    if not core:
        return None
    digit_count = sum(ch.isdigit() for ch in core)
    if len(core) >= 6 and digit_count / len(core) > 0.3:
        return TriggeredRule(
            "suspicious_domain_structure",
            "Suspicious domain structure",
            "The core domain name has an unusually high proportion of "
            "digits, a pattern more typical of auto-generated throwaway "
            "domains than a real brand or organisation name.",
            config.RULE_WEIGHTS["suspicious_domain_structure"],
        )
    return None


def _rule_http_risk(url: str) -> TriggeredRule | None:
    from urllib.parse import urlparse
    scheme = urlparse(url).scheme.lower()
    if scheme == "http":
        return TriggeredRule(
            "http_risk",
            "Plain HTTP (not HTTPS)",
            "The link uses plain HTTP instead of HTTPS, so any data sent "
            "is not encrypted in transit. This alone does not mean a link "
            "is fraudulent (older/legacy sites still use HTTP), but it is "
            "one point of caution, especially combined with other signals.",
            config.RULE_WEIGHTS["http_risk"],
        )
    return None


# Ordered exactly as in the project brief, for readability of output.
_RULES_ON_HOSTNAME = [
    _rule_ip_address_host,
    _rule_excessive_subdomains,
    _rule_excessive_hyphens,
    _rule_suspicious_tld,
    _rule_url_shortener,
    _rule_brand_impersonation,
    _rule_punycode_idn,
    _rule_suspicious_domain_structure,
]
_RULES_ON_URL = [
    _rule_suspicious_length,
    _rule_suspicious_keywords,
    _rule_login_verification_language,
    _rule_at_symbol,
    _rule_excessive_encoding,
    _rule_suspicious_query_params,
    _rule_http_risk,
]


def _risk_level_for_score(scaled_score: float) -> str:
    if scaled_score <= config.SAFE_MAX_SCORE:
        return "SAFE"
    if scaled_score <= config.SUSPICIOUS_MAX_SCORE:
        return "SUSPICIOUS"
    return "DANGEROUS"


def _summary_for(risk_level: str, triggered_count: int) -> str:
    if risk_level == "SAFE":
        return "No obvious risk detected by local checks."
    if risk_level == "SUSPICIOUS":
        return (
            f"{triggered_count} warning sign(s) detected. Proceed with caution "
            "and avoid entering personal details."
        )
    return (
        f"{triggered_count} warning sign(s) detected, including at least one "
        "strong indicator. Treat this link as likely fraudulent."
    )


def analyze_url(raw_url: str) -> DetectionResult:
    """Run all 15 local rules against a single URL and return a DetectionResult."""
    normalized = utils.normalize_url(raw_url)
    hostname = utils.get_hostname(normalized)
    is_valid = bool(hostname)

    if not is_valid:
        return DetectionResult(
            original_input=raw_url,
            normalized_url=normalized,
            hostname="",
            is_valid=False,
            raw_score=0.0,
            risk_score=0.0,
            risk_level="SUSPICIOUS",
            triggered_rules=[],
            summary=(
                "This does not look like a valid URL, so it could not be "
                "analyzed. Double-check the link before doing anything with it."
            ),
        )

    triggered: List[TriggeredRule] = []
    for rule_fn in _RULES_ON_HOSTNAME:
        result = rule_fn(hostname)
        if result:
            triggered.append(result)
    for rule_fn in _RULES_ON_URL:
        result = rule_fn(normalized)
        if result:
            triggered.append(result)

    raw_score = sum(r.score_contribution for r in triggered)
    scaled_score = min(100.0, round(raw_score, 1))
    risk_level = _risk_level_for_score(scaled_score)
    summary = _summary_for(risk_level, len(triggered))

    return DetectionResult(
        original_input=raw_url,
        normalized_url=normalized,
        hostname=hostname,
        is_valid=True,
        raw_score=raw_score,
        risk_score=scaled_score,
        risk_level=risk_level,
        triggered_rules=triggered,
        summary=summary,
    )


if __name__ == "__main__":
    # Tiny manual smoke test: python detector.py "<url>"
    import sys
    test_url = sys.argv[1] if len(sys.argv) > 1 else "https://www.sbi.co.in@secure-login-verify.tk/kyc"
    result = analyze_url(test_url)
    print(f"URL:        {result.normalized_url}")
    print(f"Domain:     {result.hostname}")
    print(f"Risk score: {result.risk_score}/100")
    print(f"Risk level: {result.risk_level}")
    print(f"Summary:    {result.summary}")
    print("Reasons:")
    for reason in result.reasons:
        print(f"  - {reason}")
