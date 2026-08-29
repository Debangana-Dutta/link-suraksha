"""
utils.py — shared, dependency-light helpers for Link Suraksha.

Kept deliberately free of any network calls or Streamlit imports so it can
be unit-tested (and reused by evaluation/evaluate.py) in isolation.
"""

import ipaddress
import re
from urllib.parse import urlparse, parse_qs, unquote

from config import HOMOGLYPH_MAP


def normalize_url(raw_url: str) -> str:
    """Best-effort normalisation of user-entered input into a URL string.

    - Trims whitespace.
    - Adds an "http://" scheme if none was given, so urlparse() can still
      extract a hostname (the missing-https itself is left for detector.py's
      http_risk rule to flag/score -- this function does not "fix" it).
    """
    url = (raw_url or "").strip()
    if not url:
        return url
    if "://" not in url:
        url = "http://" + url
    return url


def get_hostname(url: str) -> str:
    """Return the lowercased hostname of a URL, or '' if it cannot be parsed."""
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def is_ip_address(hostname: str) -> bool:
    """True if hostname is a literal IPv4 or IPv6 address."""
    if not hostname:
        return False
    # Strip brackets from IPv6 literals like [::1]
    candidate = hostname.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def get_registrable_domain(hostname: str) -> str:
    """A lightweight (non-public-suffix-list-aware) best guess at the
    "main" registrable domain, used for brand-impersonation comparisons.

    This is intentionally simple: it takes the last three labels for
    common two-part ccTLD patterns like ".co.in" / ".gov.in" / ".org.in",
    and the last two labels otherwise. It will not be perfect for every
    ccTLD in the world -- see README.md "Limitations" -- but is good
    enough for the Indian-focused brand list this project ships with.
    """
    if not hostname or is_ip_address(hostname):
        return hostname

    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname

    two_part_suffixes = {"co.in", "gov.in", "org.in", "net.in", "ac.in", "co.uk", "com.au"}
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:])
    if last_two in two_part_suffixes and len(labels) >= 3:
        return last_three
    return last_two


def count_subdomain_labels(hostname: str) -> int:
    """Number of hostname labels *beyond* the registrable domain."""
    if not hostname or is_ip_address(hostname):
        return 0
    registrable = get_registrable_domain(hostname)
    if not registrable:
        return 0
    total_labels = hostname.split(".")
    registrable_labels = registrable.split(".")
    return max(0, len(total_labels) - len(registrable_labels))


def count_hyphens(text: str) -> int:
    return (text or "").count("-")


def has_at_symbol(url: str) -> bool:
    """True if a literal '@' appears before the path -- the classic
    "https://real-looking-name@actual-destination" disguise trick.
    """
    # Look at the raw string before the scheme's "//" up through the first
    # "/" (or the end of string), since urlparse() already resolves '@'
    # into userinfo vs host and would hide the very thing we want to flag.
    after_scheme = url.split("://", 1)[-1]
    before_path = after_scheme.split("/", 1)[0]
    return "@" in before_path


def percent_encoded_count(url: str) -> int:
    return len(re.findall(r"%[0-9A-Fa-f]{2}", url))


def is_punycode(hostname: str) -> bool:
    return any(label.startswith("xn--") for label in (hostname or "").split("."))


def get_query_param_names(url: str) -> list:
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return [k.lower() for k in params.keys()]
    except ValueError:
        return []


def normalize_for_brand_match(hostname: str) -> str:
    """Lowercase + homoglyph-normalised hostname, for brand-token matching."""
    return (hostname or "").lower().translate(HOMOGLYPH_MAP)


def safe_unquote(url: str) -> str:
    try:
        return unquote(url)
    except Exception:
        return url
