"""
app.py — Link Suraksha Streamlit application.

Flow:
  URL input -> CHECK LINK -> local rule-based detection (detector.py)
  -> optional VirusTotal / Google Safe Browsing checks (threat_intelligence.py)
  -> SAFE / SUSPICIOUS / DANGEROUS verdict with plain-English explanation
  -> "Why was this flagged?" -> triggered warning signs
  -> Odia warning text (translator.py)
  -> optional spoken Odia voice alert (voice.py)

Kept as a single file for a hackathon-friendly, easy-to-read submission.
"""

import time

import streamlit as st

import config
import detector
import threat_intelligence
import translator
import voice

st.set_page_config(
    page_title="Link Suraksha",
    page_icon="🛡️",
    layout="centered",
)

# ---------------------------------------------------------------------------
# Theme: dark lavender / purple, clean, mobile-friendly
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    :root {
        --ls-bg: #1a1625;
        --ls-panel: #241f36;
        --ls-panel-border: #3a3153;
        --ls-accent: #b794f6;
        --ls-accent-2: #9f7aea;
        --ls-text: #ece6f7;
        --ls-muted: #b8aed1;
    }
    .stApp {
        background: linear-gradient(180deg, #1a1625 0%, #201b30 100%);
        color: var(--ls-text);
    }
    h1, h2, h3, h4 { color: var(--ls-text) !important; }
    .ls-tagline {
        color: var(--ls-muted);
        font-size: 1.05rem;
        margin-top: -0.6rem;
        margin-bottom: 1.4rem;
    }
    .ls-card {
        background: var(--ls-panel);
        border: 1px solid var(--ls-panel-border);
        border-radius: 16px;
        padding: 1.25rem 1.4rem;
        margin-bottom: 1.1rem;
    }
    .ls-verdict-safe {
        background: rgba(72, 187, 120, 0.12);
        border: 1px solid rgba(72, 187, 120, 0.4);
        border-radius: 16px;
        padding: 1.1rem 1.4rem;
        font-size: 1.3rem;
        font-weight: 700;
        margin-bottom: 0.9rem;
    }
    .ls-verdict-suspicious {
        background: rgba(237, 137, 54, 0.14);
        border: 1px solid rgba(237, 137, 54, 0.45);
        border-radius: 16px;
        padding: 1.1rem 1.4rem;
        font-size: 1.3rem;
        font-weight: 700;
        margin-bottom: 0.9rem;
    }
    .ls-verdict-dangerous {
        background: rgba(245, 101, 101, 0.16);
        border: 1px solid rgba(245, 101, 101, 0.5);
        border-radius: 16px;
        padding: 1.1rem 1.4rem;
        font-size: 1.3rem;
        font-weight: 700;
        margin-bottom: 0.9rem;
    }
    .ls-odia-box {
        background: var(--ls-panel);
        border: 1px solid var(--ls-accent-2);
        border-radius: 16px;
        padding: 1.1rem 1.4rem;
        font-size: 1.15rem;
        line-height: 1.9;
        margin-bottom: 1rem;
    }
    .ls-disclaimer {
        color: var(--ls-muted);
        font-size: 0.85rem;
        border-top: 1px solid var(--ls-panel-border);
        padding-top: 0.8rem;
        margin-top: 1.6rem;
    }
    .stButton>button {
        background: linear-gradient(135deg, var(--ls-accent-2), var(--ls-accent));
        color: #1a1625;
        font-weight: 700;
        border: none;
        border-radius: 12px;
        padding: 0.6rem 1.4rem;
        width: 100%;
    }
    .stTextInput>div>div>input {
        background: var(--ls-panel);
        color: var(--ls-text);
        border-radius: 10px;
        border: 1px solid var(--ls-panel-border);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

VERDICT_CSS_CLASS = {
    "SAFE": "ls-verdict-safe",
    "SUSPICIOUS": "ls-verdict-suspicious",
    "DANGEROUS": "ls-verdict-dangerous",
}

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown("# 🛡️ LINK SURAKSHA")
st.markdown('<div class="ls-tagline">"Check before you click."</div>', unsafe_allow_html=True)

with st.form("check_link_form"):
    url_input = st.text_input(
        "Paste a link to check",
        placeholder="e.g. https://example.com/some-link",
        label_visibility="collapsed",
    )
    submitted = st.form_submit_button("🔍 CHECK LINK")

use_threat_intel = st.toggle(
    "Also check with VirusTotal / Google Safe Browsing (if configured)",
    value=True,
    help="Uses your .env API keys if present. Local detection always runs regardless.",
)

if submitted:
    if not url_input or not url_input.strip():
        st.warning("Please paste a link first.")
    else:
        result = detector.analyze_url(url_input)

        # --- Optional threat intelligence (never blocks local detection) ---
        intel_results = []
        intel_elapsed = 0.0
        if use_threat_intel and result.is_valid:
            with st.spinner("Checking local rules and (if configured) online threat intelligence..."):
                intel_results, intel_elapsed = threat_intelligence.run_all_checks(result.normalized_url)

        # If any configured threat-intel source actively flagged the URL,
        # treat that as strong external corroboration and do not let it be
        # silently overridden by a low local score.
        externally_flagged = any(r.is_flagged for r in intel_results if r.status == "ok")
        effective_level = result.risk_level
        if externally_flagged and effective_level == "SAFE":
            effective_level = "SUSPICIOUS"

        # --- Verdict ---
        verdict_label = config.RISK_LEVELS[effective_level]
        st.markdown(
            f'<div class="{VERDICT_CSS_CLASS[effective_level]}">{verdict_label}</div>',
            unsafe_allow_html=True,
        )
        st.markdown(f"**{result.summary}**")
        st.caption(f"Local risk score: {result.risk_score}/100 &nbsp;|&nbsp; Domain: `{result.hostname or 'N/A'}`")

        # --- Why was this flagged? ---
        with st.expander("Why was this flagged?", expanded=bool(result.reasons)):
            if result.reasons:
                for reason in result.reasons:
                    st.markdown(f"- {reason}")
            else:
                st.markdown("No local rule was triggered for this link.")

            if intel_results:
                st.markdown("---")
                st.markdown("**Threat intelligence (optional, external)**")
                for r in intel_results:
                    st.markdown(f"- **{r.source}**: {r.detail}")
                st.caption(f"External checks took {intel_elapsed:.1f}s.")

        # --- Odia warning ---
        st.markdown("### Odia Warning / ଓଡ଼ିଆ ସତର୍କତା")
        odia_message = translator.get_verdict_message(effective_level)
        st.markdown(f'<div class="ls-odia-box">{odia_message}</div>', unsafe_allow_html=True)

        if result.reasons:
            with st.expander("ବିସ୍ତୃତ କାରଣ (Detailed reasons in Odia)"):
                odia_reasons = translator.translate_reasons(result.reasons, effective_level)
                for line in odia_reasons:
                    st.markdown(f"- {line}")

        # --- Voice alert ---
        st.markdown("### 🔊 Play Voice Alert")
        if st.button("🔊 Generate & Play Voice Alert", key="voice_btn"):
            with st.spinner("Generating Odia voice alert..."):
                voice_result = voice.generate_odia_voice_alert(odia_message)
            if voice_result.success:
                st.audio(voice_result.audio_path)
                if voice_result.engine_used != "edge-tts":
                    st.info(voice_result.message)
            else:
                st.warning(voice_result.message)

# ---------------------------------------------------------------------------
# Disclaimer
# ---------------------------------------------------------------------------
st.markdown(
    '<div class="ls-disclaimer">Link Suraksha is an awareness and screening '
    "tool. A result cannot guarantee that a website is safe.</div>",
    unsafe_allow_html=True,
)
