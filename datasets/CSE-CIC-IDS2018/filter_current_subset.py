"""
Filter the currently downloaded CSE-CIC-IDS2018 processed CSV files into a
clean subset aligned with the thesis action space.

Important:
  - This script filters by label and adds normalized target columns.
  - It does NOT convert CICFlowMeter's 80 features into the project's custom 20
    NIDS features, so the output is not a drop-in input for the current 20/34D model pipeline.
  - To keep the output manageable, common classes are downsampled with a
    deterministic reservoir sampler while rare attack classes are kept in full.

Outputs:
  datasets/CSE-CIC-IDS2018/filtered/cse_cic_ids2018_current_relevant_sampled.csv
  datasets/CSE-CIC-IDS2018/filtered/cse_cic_ids2018_current_relevant_summary.json
"""

from __future__ import annotations

import csv
import json
import random
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
PROCESSED_DIR = BASE_DIR / "processed"
FILTERED_DIR = BASE_DIR / "filtered"

INPUT_FILES = [
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
]

# Source label -> (normalized_label, target_action)
LABEL_MAP = {
    "Benign": ("benign", "Allow"),
    "Brute Force -Web": ("brute_force", "Redirect"),
    "Brute Force -XSS": ("xss", "Redirect"),
    "SQL Injection": ("sqli", "Redirect"),
    "DDOS attack-HOIC": ("ddos", "Block"),
    "DDOS attack-LOIC-UDP": ("ddos", "Block"),
}

# Keep rare labels fully; cap high-volume labels to a manageable evaluation subset.
SAMPLE_CAPS = {
    "Benign": 10000,
    "DDOS attack-HOIC": 10000,
    "DDOS attack-LOIC-UDP": None,
    "Brute Force -Web": None,
    "Brute Force -XSS": None,
    "SQL Injection": None,
}


def main() -> None:
    FILTERED_DIR.mkdir(parents=True, exist_ok=True)
    out_csv = FILTERED_DIR / "cse_cic_ids2018_current_relevant_sampled.csv"
    out_summary = FILTERED_DIR / "cse_cic_ids2018_current_relevant_summary.json"

    total_rows = 0
    kept_rows = 0
    per_source_label: dict[str, int] = {}
    per_normalized_label: dict[str, int] = {}
    per_action: dict[str, int] = {}
    sampled_rows: dict[str, list[dict[str, str]]] = {label: [] for label in LABEL_MAP}
    seen_per_label: dict[str, int] = {label: 0 for label in LABEL_MAP}
    output_fields = None
    rng = random.Random(42)

    for file_name in INPUT_FILES:
        src_path = PROCESSED_DIR / file_name
        if not src_path.exists():
            raise FileNotFoundError(f"Missing required file: {src_path}")

        with src_path.open(newline="", encoding="utf-8", errors="ignore") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None or "Label" not in reader.fieldnames:
                raise ValueError(f"Label column not found in {src_path}")

            if output_fields is None:
                output_fields = list(reader.fieldnames) + [
                    "source_file",
                    "source_label",
                    "normalized_label",
                    "target_action",
                ]

            for row in reader:
                total_rows += 1
                src_label = (row.get("Label") or "").strip()
                if src_label not in LABEL_MAP:
                    continue

                normalized_label, target_action = LABEL_MAP[src_label]
                row["source_file"] = file_name
                row["source_label"] = src_label
                row["normalized_label"] = normalized_label
                row["target_action"] = target_action

                seen_per_label[src_label] += 1
                cap = SAMPLE_CAPS.get(src_label)
                bucket = sampled_rows[src_label]
                if cap is None:
                    bucket.append(row)
                elif len(bucket) < cap:
                    bucket.append(row)
                else:
                    # Deterministic reservoir sampling
                    j = rng.randint(0, seen_per_label[src_label] - 1)
                    if j < cap:
                        bucket[j] = row

                per_source_label[src_label] = per_source_label.get(src_label, 0) + 1
                per_normalized_label[normalized_label] = (
                    per_normalized_label.get(normalized_label, 0) + 1
                )
                per_action[target_action] = per_action.get(target_action, 0) + 1

    if output_fields is None:
        raise RuntimeError("No valid input rows found.")

    with out_csv.open("w", newline="", encoding="utf-8") as out_fh:
        writer = csv.DictWriter(out_fh, fieldnames=output_fields)
        writer.writeheader()
        for src_label in sorted(sampled_rows):
            for row in sampled_rows[src_label]:
                writer.writerow(row)
                kept_rows += 1

    summary = {
        "input_dir": str(PROCESSED_DIR),
        "input_files": INPUT_FILES,
        "total_rows_scanned": total_rows,
        "rows_kept": kept_rows,
        "kept_ratio": kept_rows / total_rows if total_rows else 0.0,
        "sampling_caps": SAMPLE_CAPS,
        "per_source_label_raw": per_source_label,
        "per_normalized_label_raw": per_normalized_label,
        "per_target_action_raw": per_action,
        "per_source_label_sampled": {
            label: len(rows) for label, rows in sampled_rows.items() if rows
        },
        "note": (
            "Filtered rows still use CICFlowMeter 80-feature schema. They are suitable "
            "for label/action-level public dataset analysis, but not direct inference "
            "with the current 20-feature project model without a feature translation step."
        ),
    }
    out_summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"[OK] Wrote filtered CSV: {out_csv}")
    print(f"[OK] Wrote summary JSON: {out_summary}")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
