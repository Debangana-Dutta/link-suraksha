"""
evaluation/evaluate.py — preliminary development evaluation for Link Suraksha.

This script:
  1. Loads a labelled CSV (columns: url, label, category, reason).
  2. Runs detector.py's local rule-based analyzer on every URL.
  3. Maps the 3-level detector output (SAFE/SUSPICIOUS/DANGEROUS) to the
     2-level dataset label (SAFE/FRAUD) by treating SUSPICIOUS and
     DANGEROUS both as a "FRAUD" prediction, since the dataset itself
     only distinguishes safe vs. not-safe.
  4. Prints accuracy, precision, recall, F1, the confusion matrix, and the
     average per-URL local detection time -- all computed from the actual
     run, never hard-coded.

IMPORTANT: The numbers this script prints describe how well the current
rule set matches THIS self-authored development dataset. They are a
development sanity check, not a measurement of real-world phishing
detection performance. See data/README.md and the root README.md
"Limitations" section before quoting any number from this script anywhere
outside of internal development notes.

Usage:
    python evaluation/evaluate.py --dataset ../data/evaluation_urls.csv
    python evaluation/evaluate.py --dataset ../data/sample_urls.csv
"""

import argparse
import os
import sys
import time

import pandas as pd

# Allow running this script directly (python evaluation/evaluate.py)
# without needing the project root on PYTHONPATH already.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import detector  # noqa: E402


def map_to_binary(risk_level: str) -> str:
    """SAFE -> SAFE; SUSPICIOUS or DANGEROUS -> FRAUD (see module docstring)."""
    return "SAFE" if risk_level == "SAFE" else "FRAUD"


def evaluate(dataset_path: str) -> None:
    df = pd.read_csv(dataset_path)
    required_cols = {"url", "label"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Dataset is missing required column(s): {missing}")

    total = len(df)
    tp = fp = tn = fn = 0  # "positive" = FRAUD, "negative" = SAFE
    durations = []
    detailed_rows = []

    for _, row in df.iterrows():
        true_label = str(row["label"]).strip().upper()
        start = time.perf_counter()
        result = detector.analyze_url(str(row["url"]))
        durations.append(time.perf_counter() - start)

        predicted_label = map_to_binary(result.risk_level)

        if true_label == "FRAUD" and predicted_label == "FRAUD":
            tp += 1
        elif true_label == "SAFE" and predicted_label == "FRAUD":
            fp += 1
        elif true_label == "SAFE" and predicted_label == "SAFE":
            tn += 1
        elif true_label == "FRAUD" and predicted_label == "SAFE":
            fn += 1

        detailed_rows.append(
            {
                "url": row["url"],
                "true_label": true_label,
                "predicted_label": predicted_label,
                "risk_level": result.risk_level,
                "risk_score": result.risk_score,
                "correct": true_label == predicted_label,
            }
        )

    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    avg_time_ms = (sum(durations) / len(durations)) * 1000 if durations else 0.0

    print("=" * 70)
    print("LINK SURAKSHA -- PRELIMINARY DEVELOPMENT EVALUATION")
    print("=" * 70)
    print(f"Dataset: {dataset_path}")
    print(f"Total examples: {total}")
    print()
    print("These are preliminary results on a self-authored development")
    print("dataset. Final evaluation should use the organiser-approved")
    print("dataset when provided.")
    print()
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}  (of URLs predicted FRAUD, how many truly are)")
    print(f"Recall:    {recall:.4f}  (of truly FRAUD URLs, how many were caught)")
    print(f"F1 score:  {f1:.4f}")
    print()
    print("Confusion matrix (rows = actual, columns = predicted):")
    print(f"                  Predicted SAFE   Predicted FRAUD")
    print(f"  Actual SAFE     {tn:<16} {fp:<16}")
    print(f"  Actual FRAUD    {fn:<16} {tp:<16}")
    print()
    print(f"Average local detection time: {avg_time_ms:.3f} ms/URL")
    print("(Local rule-based checks only -- excludes any optional")
    print(" VirusTotal / Google Safe Browsing network calls.)")
    print("=" * 70)

    misclassified = [r for r in detailed_rows if not r["correct"]]
    if misclassified:
        print(f"\nMisclassified examples ({len(misclassified)}):")
        for r in misclassified:
            print(
                f"  [{r['true_label']} -> predicted {r['predicted_label']} "
                f"({r['risk_level']}, score {r['risk_score']})] {r['url']}"
            )


def main():
    parser = argparse.ArgumentParser(description="Evaluate Link Suraksha's local detector against a labelled CSV.")
    default_path = os.path.join(os.path.dirname(__file__), "..", "data", "evaluation_urls.csv")
    parser.add_argument(
        "--dataset",
        default=default_path,
        help="Path to a labelled CSV with 'url' and 'label' columns "
             "(default: data/evaluation_urls.csv). Point this at the "
             "organiser-provided dataset once available.",
    )
    args = parser.parse_args()
    evaluate(args.dataset)


if __name__ == "__main__":
    main()
