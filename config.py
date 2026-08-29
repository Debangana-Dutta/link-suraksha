"""
config.py — Link Suraksha central configuration.

Everything that is a "tunable constant" for the detector, the threat-intel
layer, and the Odia voice/translation layer lives here so it can be
inspected and adjusted in one place instead of being scattered across the
codebase.

Nothing in this file should ever contain a real API key. Keys are read
from environment variables (populated from a local .env file via
python-dotenv) inside threat_intelligence.py.
"""

import os
from dotenv import load_dotenv

# Load variables from a local .env file if present. This is a no-op (and
# perfectly safe) if the file does not exist -- the app must keep working
# with local-only detection when no keys are configured.
load_dotenv()

# ---------------------------------------------------------------------------
# Environment / API keys
# ---------------------------------------------------------------------------
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

# Network timeouts for optional threat-intel calls (seconds). Kept short so
# a slow/unreachable API never makes the app feel broken.
THREAT_INTEL_TIMEOUT_SECONDS = float(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "6"))

# ---------------------------------------------------------------------------
# Rule weights
# ---------------------------------------------------------------------------
# Each of the 15 explainable indicators in detector.py contributes points to
# a single "local risk score". These weights were chosen by hand based on
# how strong a signal each indicator is on its own, then sanity-checked by
# running evaluation/evaluate.py against data/evaluation_urls.csv and
# looking at the resulting score distribution. They are NOT derived from
# any external/organiser dataset, and they are just a starting point --
# feel free to retune them once real feedback (or the organiser dataset)
# is available.
RULE_WEIGHTS = {
    "ip_address_host": 25,
    "suspicious_length": 10,
    "excessive_subdomains": 15,
    "excessive_hyphens": 10,
    "suspicious_tld": 15,
    "url_shortener": 10,
    "suspicious_keywords": 18,       # capped total, scales with keyword hits
    "login_verification_language": 18,  # capped total, scales with hits
    "brand_impersonation": 20,
    "at_symbol": 20,
    "excessive_encoding": 12,
    "suspicious_query_params": 10,
    "punycode_idn": 18,
    "suspicious_domain_structure": 10,
    "http_risk": 8,
}

# Unlike an earlier draft, the risk score is NOT scaled by the sum of all
# 15 weights -- doing so diluted every individual rule too much, since it
# is very rare (and not required) for all 15 rules to fire on one URL.
# Instead, the raw summed score IS the risk score, simply capped at 100.
# This keeps each rule's contribution meaningful and directly matches the
# thresholds below (which were tuned by running
# evaluation/evaluate.py against data/evaluation_urls.csv and inspecting
# the resulting score distribution and confusion matrix).

# ---------------------------------------------------------------------------
# Risk-level thresholds (on the 0-100 raw/capped score)
# ---------------------------------------------------------------------------
# These were picked so that:
#   - a single weak/ambiguous signal (e.g. plain HTTP alone, or one mild
#     keyword) does not by itself push a URL out of SAFE,
#   - a single strong signal (e.g. an IP-address host, the @ symbol,
#     punycode, or brand impersonation) is enough on its own to reach at
#     least SUSPICIOUS,
#   - DANGEROUS requires either one very strong signal plus a supporting
#     one, or several moderate signals stacking together (the
#     "combined_multiple_indicators" pattern in the dataset).
# Document any change here alongside a re-run of evaluation/evaluate.py.
SAFE_MAX_SCORE = 9           # score <= this  -> SAFE
SUSPICIOUS_MAX_SCORE = 34    # this < score <= this -> SUSPICIOUS
# anything above SUSPICIOUS_MAX_SCORE -> DANGEROUS

RISK_LEVELS = {
    "SAFE": "🟢 SAFE",
    "SUSPICIOUS": "🟠 SUSPICIOUS",
    "DANGEROUS": "🔴 DANGEROUS",
}

# ---------------------------------------------------------------------------
# Keyword / pattern lists used by detector.py
# ---------------------------------------------------------------------------

# General urgency / scare / reward keywords (rule: suspicious_keywords)
SUSPICIOUS_KEYWORDS = [
    "urgent", "immediate", "suspend", "suspended", "locked", "lock",
    "limited", "expire", "expires", "expiring", "required", "pending",
    "warning", "alert", "restricted", "unusual-activity", "final",
    "congratulations", "winner", "selected", "claim", "free", "gift",
    "lucky", "draw", "reward", "prize", "overdue", "now",
]

# Login / verification / KYC / payment specific language
# (rule: login_verification_language)
LOGIN_VERIFICATION_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "kyc", "update", "account", "payment", "pay", "refund", "billing",
    "invoice", "otp", "password", "reset", "secure", "confirm",
    "security", "identity",
]

# Domains that are well-known URL shorteners (rule: url_shortener)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
    "bl.ink", "rb.gy", "tiny.cc", "lnkd.in",
}

# TLDs frequently associated with abuse / low-cost bulk registration
# (rule: suspicious_tld). This is a heuristic list, not a definitive one --
# plenty of legitimate sites use these TLDs too, which is why this rule
# contributes a moderate weight rather than an automatic DANGEROUS verdict.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "rest", "zip", "mov", "loan", "win", "bid", "gdn", "kim", "men",
    "party", "review", "science", "date", "stream",
}

# Recognisable Indian/global brand tokens used to detect impersonation
# patterns (rule: brand_impersonation). The check looks for these tokens
# appearing in a hostname that is NOT the brand's own official domain.
BRAND_TOKENS = [
    "sbi", "hdfc", "hdfcbank", "icici", "icicibank", "axisbank", "axis",
    "pnb", "rbi", "npci", "paytm", "phonepe", "googlepay", "amazon",
    "flipkart", "myntra", "meesho", "google", "microsoft", "facebook",
    "whatsapp", "instagram", "irctc", "uidai", "aadhaar", "incometax",
    "digilocker",
]

# The "official" registrable domains for the brands above, so that the
# brand-impersonation rule does not flag a brand's own real website.
OFFICIAL_BRAND_DOMAINS = {
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "pnbindia.in", "rbi.org.in", "npci.org.in", "paytm.com",
    "phonepe.com", "pay.google.com", "amazon.in", "amazon.com",
    "flipkart.com", "myntra.com", "meesho.com", "google.com",
    "microsoft.com", "facebook.com", "whatsapp.com", "instagram.com",
    "irctc.co.in", "uidai.gov.in", "incometax.gov.in", "digilocker.gov.in",
    "mygov.in", "india.gov.in", "odisha.gov.in",
}

# Character-substitution homoglyphs commonly used in brand impersonation
# (e.g. "amaz0n" instead of "amazon"). Used to widen the brand match.
HOMOGLYPH_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a"})

# Suspicious query-parameter names (rule: suspicious_query_params)
SUSPICIOUS_QUERY_PARAM_NAMES = {
    "user", "username", "pass", "password", "pwd", "token", "otp",
    "redirect", "redirect_url", "redirecturl", "next", "return_url",
    "returnurl", "session", "auth",
}

# ---------------------------------------------------------------------------
# Thresholds used by individual rules
# ---------------------------------------------------------------------------
LONG_URL_LENGTH_THRESHOLD = 75        # characters, whole URL
LONG_PATH_LENGTH_THRESHOLD = 40       # characters, path only
MAX_SUBDOMAIN_LABELS = 4              # hostname labels beyond this -> flagged
MAX_HYPHENS_IN_HOST = 2               # hyphens in hostname beyond this -> flagged
MAX_PERCENT_ENCODED_CHARS = 2         # "%XX" occurrences beyond this -> flagged

# ---------------------------------------------------------------------------
# Odia strings
# ---------------------------------------------------------------------------
# Curated, natural-language Odia messages for the three verdict levels.
# These are used as-is (not machine-translated) because they are the most
# important, highest-visibility strings in the app and deserve to read
# naturally. Per-URL "reasons" are machine-translated at runtime via
# translator.py, with these same three messages used as the safe fallback
# if that machine translation fails for any reason.
ODIA_VERDICT_MESSAGES = {
    "SAFE": "ଏହି ଲିଙ୍କରେ କୌଣସି ସ୍ପଷ୍ଟ ବିପଦ ଚିହ୍ନଟ ହୋଇନାହିଁ।",
    "SUSPICIOUS": "ସତର୍କ ରୁହନ୍ତୁ। ଏହି ଲିଙ୍କରେ ସନ୍ଦେହଜନକ ଲକ୍ଷଣ ରହିଛି।",
    "DANGEROUS": "ସତର୍କ! ଏହି ଲିଙ୍କ ଠକାମି ହୋଇପାରେ। ଆପଣଙ୍କ ପାସୱାର୍ଡ କିମ୍ବା OTP ଦିଅନ୍ତୁ ନାହିଁ।",
}

# gTTS was checked programmatically against gtts.lang.tts_langs() during
# development and does NOT include Odia ("or") as a supported code -- only
# Hindi and other larger Indian languages are present. Per the "verify,
# don't assume" requirement, Link Suraksha therefore uses Microsoft Edge's
# neural voice service (the `edge-tts` package) for Odia speech, since
# Odia neural voices (or-IN-SubhasiniNeural / or-IN-SukantNeural) are
# genuinely published by Microsoft. See voice.py and README.md for details
# and for the fallback chain if that service is unreachable.
ODIA_TTS_VOICE = os.getenv("ODIA_TTS_VOICE", "or-IN-SubhasiniNeural")
FALLBACK_TTS_LANG = "en"  # gTTS language code used if Odia voice generation fails
GTTS_VERIFIED_ODIA_SUPPORTED = False  # verified False at build time; kept as a named flag so this can be re-checked and flipped later without hunting through voice.py
