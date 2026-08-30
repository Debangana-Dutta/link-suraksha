"""
voice.py — Reliable voice alert for Link Suraksha.
"""

import os
import tempfile
from dataclasses import dataclass
from typing import Optional

import config


@dataclass
class VoiceResult:
    success: bool
    audio_path: Optional[str]
    engine_used: str
    message: str


def generate_odia_voice_alert(odia_text: str) -> VoiceResult:
    """Generate an English spoken warning while displaying Odia on screen."""

    if not odia_text or not odia_text.strip():
        return VoiceResult(
            False,
            None,
            "none",
            "No text was provided for the voice alert.",
        )

    fallback_text = (
        "Warning. Link Suraksha has detected a potential security risk. "
        "Please check the warning signs carefully before opening this link."
    )

    try:
        from gtts import gTTS

        output_path = os.path.join(
            tempfile.gettempdir(),
            "link_suraksha_voice_alert.mp3",
        )

        tts = gTTS(
            text=fallback_text,
            lang="en",
        )

        tts.save(output_path)

        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            return VoiceResult(
                True,
                output_path,
                "gTTS-fallback",
                "Voice alert generated in English. "
                "The complete Odia warning is displayed on screen.",
            )

        return VoiceResult(
            False,
            None,
            "none",
            "Voice alert could not be generated.",
        )

    except Exception as e:
        return VoiceResult(
            False,
            None,
            "none",
            f"Voice generation failed: {e}",
        )
