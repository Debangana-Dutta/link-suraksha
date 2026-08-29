# Link Suraksha — Development & Evaluation Datasets

## Purpose

These CSV files exist to support **development and internal testing** of the
Link Suraksha URL-based phishing/suspicious-link detector while the
application logic (URL parsing, rule-based scoring, VirusTotal / Google Safe
Browsing lookups, Odia translation and text-to-speech) is being built.

They are **not** a substitute for the official dataset that the
AI Kavach | Terrier Cyber Quest 2026 organisers may provide, and they are
**not** a record of real-world phishing incidents.

## Files

### `sample_urls.csv` (35 rows)
A small, hand-picked subset covering the major URL patterns Link Suraksha is
meant to detect (government/education/banking/e-commerce/news sites on the
SAFE side; suspicious logins, fake KYC/refund/prize messages, IP-address
URLs, `@`-symbol tricks, excessive hyphens/subdomains, suspicious TLDs, etc.
on the FRAUD side). It is intended for:
- Quick local development and debugging.
- Live demonstration during the hackathon, where a smaller, easy-to-read
  dataset is more practical to show on screen than a 100+ row file.

### `evaluation_urls.csv` (118 rows: 57 SAFE / 61 FRAUD)
A larger, more evenly balanced dataset intended for computing **preliminary,
internal development metrics only** (e.g. a rough accuracy/precision/recall
check while iterating on the rule set). Every row's `label` is internally
consistent with the pattern described in its `category` and `reason` fields.

## Important limitations — please read before using these numbers anywhere

- **These are not "50 real links."** All FRAUD-labelled rows use synthetic
  domains (mostly ending in `.example-fraud.test`), well-known abusive TLD
  patterns (`.tk`, `.xyz`, `.top`), or IP addresses drawn from documentation
  ranges (e.g. `203.0.113.0/24`, `192.0.2.0/24`) and private ranges
  (`192.168.x.x`, `10.x.x.x`). None of them are active malicious websites,
  and none of them were collected from a real phishing campaign.
- **No credentials, OTPs, personal data, malware, or exploit payloads** are
  included anywhere in these files.
- **URL shorteners** (`bit.ly`, `tinyurl.com`, `t.co` examples) are labelled
  FRAUD here purely so the rule-based detector has a labelled example of the
  "shortened link hides the destination" *feature*. In the real world,
  shorteners are used legitimately far more often than maliciously — do not
  present this simplification as evidence that shorteners are inherently
  fraudulent.
- **HTTP is a risk signal, not an automatic fraud label.** Several SAFE rows
  (`category = http_legacy`) intentionally use `http://` to show that plain
  HTTP alone should not flip a verdict to FRAUD; the FRAUD rows tagged
  `http_risk_signal` combine HTTP with other indicators (hyphenated domain,
  IP-address host, etc.).
- **Any accuracy, precision, or recall number computed from this dataset is
  a development-time sanity check only.** It says something about how well
  the current rule set matches the synthetic patterns *in this file* — it is
  **not** a claim about real-world detection performance, and must not be
  quoted as if it were (e.g. do not present it in a slide as "94% accuracy"
  or similar without clearly labelling it as a result on a synthetic,
  self-authored development set).

## Using the official hackathon dataset

If AI Kavach | Terrier Cyber Quest 2026 organisers release an official
evaluation dataset, `detector.py` (or the evaluation script) should be
pointed at that file instead of `evaluation_urls.csv` for any results used
in the final submission, demo, or presentation. The column schema
(`url,label,category,reason`) was chosen to make that swap straightforward —
as long as the organiser-provided file uses the same `url` and `label`
columns (or is mapped to them), no code changes should be required beyond
the file path.

## Column schema

| Column     | Description                                                        |
|------------|----------------------------------------------------------------------|
| `url`      | The URL string being classified.                                   |
| `label`    | `SAFE` or `FRAUD`.                                                  |
| `category` | The type of example (e.g. `banking`, `fake_kyc`, `excessive_hyphens`). |
| `reason`   | A short, human-readable explanation for the label — useful for building an *explainable* rule-based detector. |
