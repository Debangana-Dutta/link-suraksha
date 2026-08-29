# Link Suraksha — Evaluation

`evaluate.py` runs the local rule-based detector (`detector.py`) against a
labelled CSV and prints real, freshly-computed metrics: accuracy,
precision, recall, F1, a confusion matrix, and average local detection
time. Nothing in this script's output is hard-coded — every number comes
from the actual run.

## Running it

From the project root:

```bash
python evaluation/evaluate.py --dataset data/evaluation_urls.csv
```

or, for the smaller demo set:

```bash
python evaluation/evaluate.py --dataset data/sample_urls.csv
```

`--dataset` is the only argument, and it accepts any CSV with `url` and
`label` columns — so it's a one-line change to point this at the official
AI Kavach | Terrier Cyber Quest 2026 dataset once the organisers provide
one:

```bash
python evaluation/evaluate.py --dataset path/to/organiser_dataset.csv
```

## How predictions are scored

`detector.py` outputs one of three risk levels: `SAFE`, `SUSPICIOUS`, or
`DANGEROUS`. The evaluation dataset only labels URLs as `SAFE` or `FRAUD`.
To compare them, `evaluate.py` treats `SUSPICIOUS` and `DANGEROUS` both as
a "FRAUD" prediction — only a `SAFE` verdict counts as a "SAFE"
prediction. This is documented in the script itself so the mapping isn't
hidden.

## Reading the results honestly

**These are preliminary results on a self-authored development dataset.
Final evaluation should use the organiser-approved dataset when
provided.**

A few things worth remembering before quoting any number this script
prints, in a presentation or anywhere else:

- The dataset it runs against by default (`data/evaluation_urls.csv`) is
  synthetic — see `data/README.md`. A high score here mostly shows that
  the rules match the patterns *this same project* generated; it is not
  independent evidence of real-world accuracy.
- Precision/recall here are with respect to the FRAUD class specifically
  (see the confusion-matrix labelling in the printed output).
- If you re-run this after tuning `config.py`'s weights or thresholds,
  re-run it against the same dataset both before and after so any
  reported change is a real, reproducible comparison rather than a
  cherry-picked number.
