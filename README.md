# 🛡️ Link Suraksha

**"Check before you click."**

A lightweight, explainable phishing/suspicious-link screening tool built
for **AI Kavach | Terrier Cyber Quest 2026**, with an Odia-language
explanation and voice alert so the warning reaches people who are more
comfortable reading or hearing Odia than English.

---

## 1. Project overview

Link Suraksha takes a single URL, runs it through 15 explainable,
rule-based checks (no ML black box, no GPU required), optionally
corroborates that with VirusTotal / Google Safe Browsing, and returns a
plain-English **and** plain-Odia verdict: 🟢 SAFE, 🟠 SUSPICIOUS, or 🔴
DANGEROUS — along with the exact reasons behind that verdict and a spoken
Odia voice alert.

## 2. Problem

Phishing and "fake KYC/refund/prize" links spread fastest through
WhatsApp/SMS forwards, and disproportionately reach people who are
least equipped to spot the warning signs of a fake link — including
elderly and rural users who read and speak Odia more comfortably than
English, and who may not have data-heavy antivirus tools installed.

## 3. Solution

A single-page, mobile-friendly Streamlit app: paste a link, tap **CHECK
LINK**, and get an immediate, explainable verdict — with every flagged
signal listed in plain language, a natural-Odia translation of the
warning, and an optional spoken Odia alert for people who'd rather listen
than read.

## 4. Why Odia + voice

Odisha has a large population more fluent in Odia than English, and text
alone still excludes low-literacy users. Pairing a plain-English
explanation with natural Odia text *and* a spoken Odia alert makes the
tool usable by a much wider audience than an English-only or text-only
tool would reach — while remaining lightweight enough to run without a
GPU or heavy install.

## 5. Features

- 15 named, independently explainable URL-level fraud indicators
- A 0–100 local risk score with documented thresholds
- Optional VirusTotal + Google Safe Browsing corroboration (works fully
  without either — see [Environment variables](#11-environment-variables))
- Never claims a link is "definitely safe" — worst case, "no obvious risk
  detected by local checks"
- Natural-language Odia translation of every verdict, with a safe fallback
  if machine translation is unavailable
- Spoken Odia voice alert via a **verified** Odia-capable TTS engine (see
  [Section 15](#15-limitations))
- Dark lavender, mobile-friendly UI designed to be usable by non-technical
  and elderly users
- `evaluation/evaluate.py` for transparent, real (never hard-coded)
  accuracy/precision/recall numbers on a labelled dataset

## 6. Architecture

```
URL Input
   │
   ▼
URL Validation           (utils.py, detector.py)
   │
   ▼
Rule Filter               15 explainable indicators -> local risk score
   │                       (detector.py, config.py)
   ▼
Threat Intelligence       optional VirusTotal / Google Safe Browsing
   │                       (threat_intelligence.py) — skipped gracefully
   │                       if no key is configured or a call fails
   ▼
Risk Assessment           SAFE / SUSPICIOUS / DANGEROUS + reasons
   │
   ▼
Odia Explanation          curated verdict text + translated reasons
   │                       (translator.py)
   ▼
Voice Alert               spoken Odia (or labelled English fallback)
                           (voice.py)
```

## 7. Tech stack

| Layer | Choice |
|---|---|
| UI | Streamlit |
| URL parsing | `urllib.parse`, regular expressions |
| Data | `pandas` |
| Config / secrets | `python-dotenv` |
| Threat intel (optional) | VirusTotal API, Google Safe Browsing API |
| Translation | `deep-translator` (Google Translate backend, verified "or" support) |
| Odia voice | `edge-tts` (Microsoft neural voices — verified genuine Odia support) |
| English voice fallback | `gTTS` |

## 8. Project structure

```
LinkSuraksha/
├── app.py                  # Streamlit UI
├── detector.py              # 15 explainable local rules + scoring
├── threat_intelligence.py   # optional VirusTotal / Google Safe Browsing
├── translator.py            # English -> Odia
├── voice.py                 # Odia text-to-speech (+ fallback chain)
├── config.py                 # weights, thresholds, keyword/TLD/brand lists
├── utils.py                  # URL parsing helpers
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md                 # this file
├── data/
│   ├── sample_urls.csv       # ~35-row demo dataset
│   ├── evaluation_urls.csv   # ~118-row development evaluation dataset
│   └── README.md             # dataset scope & limitations (read this!)
├── evaluation/
│   ├── evaluate.py           # computes real accuracy/precision/recall/F1
│   └── README.md
└── screenshots/
    └── .gitkeep
```

## 9. Installation

Requires Python 3.10+.

```bash
git clone <your-repo-url>
cd LinkSuraksha
python -m venv venv
source venv/bin/activate        # macOS/Linux
pip install -r requirements.txt
cp .env.example .env            # then optionally fill in API keys
```

## 10. Windows setup commands

```bat
git clone <your-repo-url>
cd LinkSuraksha
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

If `python` isn't recognized, try `py -3 -m venv venv` instead.

## 11. Environment variables

Set these in a local `.env` file (never commit it — see `.gitignore`).
Both are **optional**; the local rule-based detector works fully without
either one.

| Variable | Purpose |
|---|---|
| `VIRUSTOTAL_API_KEY` | Enables VirusTotal lookups. Leave blank to skip. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Enables Safe Browsing lookups. Leave blank to skip. |
| `ODIA_TTS_VOICE` | Optional. Defaults to `or-IN-SubhasiniNeural`; `or-IN-SukantNeural` is also available. |

## 12. How to run

```bash
streamlit run app.py
```

This opens the app at `http://localhost:8501`.

## 13. How to evaluate

```bash
python evaluation/evaluate.py --dataset data/evaluation_urls.csv
```

Prints real accuracy, precision, recall, F1, a confusion matrix, and
average local detection time — computed live from that run, never
hard-coded. See `evaluation/README.md` for details, and read
[Section 15](#15-limitations) before quoting any number from it.

## 14. Dataset explanation

`data/sample_urls.csv` (~35 rows) is a small demo set for live
walkthroughs. `data/evaluation_urls.csv` (~118 rows, roughly balanced
SAFE/FRAUD) is a larger set for preliminary development metrics. **Both
are self-authored, synthetic development datasets — not real captured
phishing traffic, and not the official hackathon dataset.** Full details,
including exactly what's synthetic and why, are in `data/README.md` —
please read it before reusing any number from these files in a
presentation.

## 15. Limitations

- **Rule-based, not ML.** The 15 indicators are hand-designed heuristics.
  They will both miss cleverly-disguised phishing links (false negatives)
  and occasionally flag legitimate links that happen to contain words
  like "account" or "verify" (false positives) — e.g. in internal testing,
  `accounts.google.com/signin` (a genuinely safe Google URL) is flagged
  SUSPICIOUS because its hostname contains "account", which is also a
  common word in real phishing domains. This is a known, accepted
  trade-off of a transparent, offline rule set, and is exactly the kind of
  case a future ML model trained on an organiser-approved dataset should
  improve on.
- **Domain parsing is a simplified heuristic**, not a full public-suffix-
  list implementation — it special-cases a handful of common Indian
  two-part suffixes (`.co.in`, `.gov.in`, etc.) but is not exhaustive for
  every ccTLD worldwide.
- **Odia TTS uses Microsoft's Edge neural voice service (`edge-tts`), not
  gTTS.** During development, gTTS's own supported-language list was
  checked in code (`gtts.lang.tts_langs()`) and does **not** include Odia
  ("or") — only larger Indian languages such as Hindi are present.
  Microsoft does publish genuine Odia neural voices
  (`or-IN-SubhasiniNeural`, `or-IN-SukantNeural`), so those are used
  instead, with an English gTTS fallback (clearly labelled as such in the
  UI) if the voice service is ever unreachable.
- **Translation quality** for the per-URL "reasons" depends on Google
  Translate's Odia support via `deep-translator`, which can occasionally
  produce awkward phrasing for technical terms; the three main verdict
  messages are hand-written Odia specifically to avoid this for the most
  important text in the app.
- **Threat-intelligence checks are best-effort.** Without API keys, or if
  a request times out or errors, the app silently falls back to
  local-only detection rather than blocking the result.
- **No result is a guarantee.** See the in-app disclaimer and
  [Section 16](#16-responsible-use).

## 16. Responsible use

- Link Suraksha is a **cyber-awareness and screening tool**, not a
  guarantee of safety.
- It does **not** collect passwords, OTPs, or personal information — it
  only ever processes the URL string you paste in.
- It does **not** attack, exploit, crawl aggressively, or submit
  credentials to any real system; the only outbound calls it makes are
  read-only reputation lookups to VirusTotal / Google Safe Browsing (only
  if you've configured those keys) and to the translation/voice services.
- Testing should follow the hackathon's requirement of using only an
  organiser-provided sandbox/simulated environment, and should never use
  real personal data.

## 17. Future scope

- WhatsApp Bot integration, so links can be checked directly where most
  scam forwards are received
- Chrome Extension for inline link warnings while browsing
- Expansion to 10 Indian languages beyond Odia
- An improved ML-based model, trained once an organiser-approved labelled
  dataset is available, to reduce the false positives/negatives inherent
  to the current rule-based approach
- Better offline/edge support for low-connectivity areas

---

*Built for AI Kavach | Terrier Cyber Quest 2026. Do not present the
development dataset as real phishing data, and do not present
`evaluate.py`'s output as a measurement of real-world accuracy — see
Sections 14 and 15 above.*
