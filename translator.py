"""
translator.py — English -> Odia translation for Link Suraksha.

Two tiers, by design:

1. The three main verdict messages (SAFE / SUSPICIOUS / DANGEROUS) are
   curated, natural-sounding Odia text (config.ODIA_VERDICT_MESSAGES),
   used as-is. These are the most important, highest-visibility strings
   in the whole app, so they are not machine-translated at runtime.

2. The per-URL "reasons" list (which varies for every URL and can't be
   hand-written in advance) is machine-translated using deep-translator's
   Google Translate backend, verified during development to list "Odia
   (Oriya)" -> language code "or" as a supported target. If that call
   fails for any reason (no internet, package/API issue, rate limit),
   translate_text() falls back to the closest tier-1 Odia verdict message
   instead of crashing or showing raw English where Odia was expected.
"""

from typing import List

from deep_translator import GoogleTranslator
from deep_translator.exceptions import NotValidPayload, TranslationNotFound

import config

_ODIA_LANG_CODE = "or"


def get_verdict_message(risk_level: str) -> str:
    """Curated, natural Odia text for a risk level. Always succeeds."""
    return config.ODIA_VERDICT_MESSAGES.get(
        risk_level, config.ODIA_VERDICT_MESSAGES["SUSPICIOUS"]
    )


def translate_text(text: str, risk_level: str = "SUSPICIOUS") -> str:
    """Translate a single short English string to Odia.

    On any failure, returns the tier-1 curated Odia message for
    `risk_level` instead of raising or returning English text, so the UI
    always shows *something* meaningful in Odia.
    """
    if not text:
        return get_verdict_message(risk_level)
    try:
        translated = GoogleTranslator(source="en", target=_ODIA_LANG_CODE).translate(text)
        if translated:
            return translated
        return get_verdict_message(risk_level)
    except (NotValidPayload, TranslationNotFound):
        return get_verdict_message(risk_level)
    except Exception:
        # deep-translator can raise a range of network/HTTP errors; treat
        # all of them the same way -- fail safe, never crash the app.
        return get_verdict_message(risk_level)


def translate_reasons(reasons: List[str], risk_level: str) -> List[str]:
    """Translate a list of reason strings, one call per reason.

    If translation is unavailable, returns a single-item list containing
    the tier-1 curated fallback message rather than a list of failures,
    so the UI doesn't show a wall of repeated fallback text.
    """
    if not reasons:
        return []
    translated = []
    any_failure = False
    for reason in reasons:
        try:
            result = GoogleTranslator(source="en", target=_ODIA_LANG_CODE).translate(reason)
            if result:
                translated.append(result)
            else:
                any_failure = True
                break
        except Exception:
            any_failure = True
            break
    if any_failure or not translated:
        return [get_verdict_message(risk_level)]
    return translated
