"""
app.py — Link Suraksha Streamlit application.

Flow:
    URL input
        -> local rule-based detection
        -> optional threat intelligence
        -> SAFE / SUSPICIOUS / DANGEROUS verdict
        -> reasons
        -> Odia warning
        -> voice alert

The checked result is stored in Streamlit session state so that
the voice button works correctly across Streamlit reruns.
"""

import streamlit as st

import config
import detector
import threat_intelligence
import translator
import voice


# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Link Suraksha",
    page_icon="🛡️",
    layout="centered",
)


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

if "analysis" not in st.session_state:
    st.session_state.analysis = None

if "voice_result" not in st.session_state:
    st.session_state.voice_result = None


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
        background: linear-gradient(
            180deg,
            #1a1625 0%,
            #201b30 100%
        );
        color: var(--ls-text);
    }

    h1, h2, h3, h4 {
        color: var(--ls-text) !important;
    }

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

    .stButton > button {
        background: linear-gradient(
            135deg,
            var(--ls-accent-2),
            var(--ls-accent)
        );
        color: #1a1625;
        font-weight: 700;
        border: none;
        border-radius: 12px;
        padding: 0.6rem 1.4rem;
        width: 100%;
    }

    .stTextInput > div > div > input {
        background: var(--ls-panel);
        color: var(--ls-text);
        border-radius: 10px;
        border: 1px solid var(--ls-panel-border);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Verdict styling
# ---------------------------------------------------------------------------

VERDICT_CSS_CLASS = {
    "SAFE": "ls-verdict-safe",
    "SUSPICIOUS": "ls-verdict-suspicious",
    "DANGEROUS": "ls-verdict-dangerous",
}


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown("# 🛡️ LINK SURAKSHA")

st.markdown(
    '<div class="ls-tagline">"Check before you click."</div>',
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# URL input
# ---------------------------------------------------------------------------

with st.form("check_link_form"):

    url_input = st.text_input(
        "Paste a link to check",
        placeholder="e.g. https://example.com/some-link",
        label_visibility="collapsed",
    )

    submitted = st.form_submit_button(
        "🔍 CHECK LINK",
        use_container_width=True,
    )


# ---------------------------------------------------------------------------
# Threat intelligence option
# ---------------------------------------------------------------------------

use_threat_intel = st.toggle(
    "Also check with VirusTotal / Google Safe Browsing (if configured)",
    value=True,
    help=(
        "Uses your .env API keys if present. "
        "Local detection always runs regardless."
    ),
)


# ---------------------------------------------------------------------------
# Run analysis
# ---------------------------------------------------------------------------

if submitted:

    if not url_input or not url_input.strip():

        st.warning("Please paste a link first.")

        st.session_state.analysis = None
        st.session_state.voice_result = None

    else:

        # Reset previous voice result for a new URL.
        st.session_state.voice_result = None

        with st.spinner("Analyzing link..."):

            result = detector.analyze_url(url_input)

            # ---------------------------------------------------------------
            # Optional threat intelligence
            # ---------------------------------------------------------------

            intel_results = []
            intel_elapsed = 0.0

            if use_threat_intel and result.is_valid:

                with st.spinner(
                    "Checking local rules and optional online "
                    "threat intelligence..."
                ):

                    (
                        intel_results,
                        intel_elapsed,
                    ) = threat_intelligence.run_all_checks(
                        result.normalized_url
                    )

            # ---------------------------------------------------------------
            # External corroboration
            # ---------------------------------------------------------------

            externally_flagged = any(
                r.is_flagged
                for r in intel_results
                if r.status == "ok"
            )

            effective_level = result.risk_level

            if (
                externally_flagged
                and effective_level == "SAFE"
            ):
                effective_level = "SUSPICIOUS"

            # ---------------------------------------------------------------
            # Generate Odia warning
            # ---------------------------------------------------------------

            odia_message = translator.get_verdict_message(
                effective_level
            )

            # ---------------------------------------------------------------
            # Store everything required for rendering
            # ---------------------------------------------------------------

            st.session_state.analysis = {
                "result": result,
                "intel_results": intel_results,
                "intel_elapsed": intel_elapsed,
                "effective_level": effective_level,
                "odia_message": odia_message,
            }


# ---------------------------------------------------------------------------
# Display stored analysis
# ---------------------------------------------------------------------------

analysis = st.session_state.analysis

if analysis is not None:

    result = analysis["result"]
    intel_results = analysis["intel_results"]
    intel_elapsed = analysis["intel_elapsed"]
    effective_level = analysis["effective_level"]
    odia_message = analysis["odia_message"]

    # -----------------------------------------------------------------------
    # Verdict
    # -----------------------------------------------------------------------

    verdict_label = config.RISK_LEVELS[effective_level]

    st.markdown(
        f'<div class="{VERDICT_CSS_CLASS[effective_level]}">'
        f"{verdict_label}"
        f"</div>",
        unsafe_allow_html=True,
    )

    st.markdown(f"**{result.summary}**")

    st.caption(
        f"Local risk score: {result.risk_score}/100 "
        f"&nbsp;|&nbsp; "
        f"Domain: `{result.hostname or 'N/A'}`"
    )

    # -----------------------------------------------------------------------
    # Why was this flagged?
    # -----------------------------------------------------------------------

    with st.expander(
        "Why was this flagged?",
        expanded=bool(result.reasons),
    ):

        if result.reasons:

            for reason in result.reasons:
                st.markdown(f"- {reason}")

        else:

            st.markdown(
                "No local rule was triggered for this link."
            )

        if intel_results:

            st.markdown("---")

            st.markdown(
                "**Threat intelligence (optional, external)**"
            )

            for intel in intel_results:

                st.markdown(
                    f"- **{intel.source}**: {intel.detail}"
                )

            st.caption(
                f"External checks took "
                f"{intel_elapsed:.1f}s."
            )

    # -----------------------------------------------------------------------
    # Odia warning
    # -----------------------------------------------------------------------

    st.markdown(
        "### Odia Warning / ଓଡ଼ିଆ ସତର୍କତା"
    )

    st.markdown(
        f'<div class="ls-odia-box">{odia_message}</div>',
        unsafe_allow_html=True,
    )

    # -----------------------------------------------------------------------
    # Detailed Odia reasons
    # -----------------------------------------------------------------------

    if result.reasons:

        with st.expander(
            "ବିସ୍ତୃତ କାରଣ (Detailed reasons in Odia)"
        ):

            odia_reasons = translator.translate_reasons(
                result.reasons,
                effective_level,
            )

            for line in odia_reasons:
                st.markdown(f"- {line}")

    # -----------------------------------------------------------------------
    # Voice alert
    # -----------------------------------------------------------------------

    st.markdown("### 🔊 Play Voice Alert")

    st.caption(
        "The warning is displayed in Odia. "
        "The current spoken voice uses an English fallback."
    )

    if st.button(
        "🔊 Generate & Play Voice Alert",
        key="voice_btn",
        type="primary",
        use_container_width=True,
    ):

        with st.spinner("Generating voice alert..."):

            voice_result = (
                voice.generate_odia_voice_alert(
                    odia_message
                )
            )

        # Store voice result so it survives Streamlit reruns.
        st.session_state.voice_result = voice_result

    # -----------------------------------------------------------------------
    # Display voice result
    # -----------------------------------------------------------------------

    voice_result = st.session_state.voice_result

    if voice_result is not None:

        if (
            voice_result.success
            and voice_result.audio_path
        ):

            st.success(
                "🔊 Voice alert generated successfully."
            )

            st.audio(
                voice_result.audio_path,
                format="audio/mp3",
            )

            if (
                voice_result.engine_used
                == "gTTS-fallback"
            ):

                st.info(
                    "The spoken warning is currently in English. "
                    "The complete warning remains available above "
                    "in Odia."
                )

        else:

            st.error(
                voice_result.message
            )


# ---------------------------------------------------------------------------
# Disclaimer
# ---------------------------------------------------------------------------

st.markdown(
    '<div class="ls-disclaimer">'
    "Link Suraksha is an awareness and screening tool. "
    "A result cannot guarantee that a website is safe."
    "</div>",
    unsafe_allow_html=True,
)
