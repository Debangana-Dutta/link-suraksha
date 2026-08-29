"""
voice.py — Reliable voice alert for Link Suraksha.

Primary voice engine:
- gTTS English audio fallback

Odia text remains displayed on screen because gTTS does not
provide verified Odia language support.
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
    """
    Generate a voice alert.

    The Odia warning is shown on screen, while the spoken alert
    uses English because gTTS does not provide verified Odia support.
    """

    if not odia_text or not odia_text.strip():
        return VoiceResult(
            False,
            None,
            "none",
            "No text was provided for the voice alert."
        )

    fallback_text = (
        "Warning. Link Suraksha has detected a potential security risk. "
        "Please check the warning signs carefully before opening this link."
    )

    try:
        from gtts import gTTS

        output_path = os.path.join(
            tempfile.gettempdir(),
            "link_suraksha_voice_alert.mp3"
        )

        tts = gTTS(
            text=fallback_text,
            lang="en"
        )

        tts.save(output_path)

        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            return VoiceResult(
                True,
                output_path,
                "gTTS-fallback",
                "Voice alert generated in English. "
                "The Odia warning is displayed on screen."
            )

    except Exception as e:
        return VoiceResult(
            False,
            None,
            "none",
            f"Voice generation failed: {e}"
        )

    return VoiceResult(
        False,
        None,
        "none",
        "Voice alert could not be generated."
    )