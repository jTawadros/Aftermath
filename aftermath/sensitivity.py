# sensitivity.py

from collections import Counter
from pathlib import Path
from aftermath.manifest_query import load_manifest


SENSITIVE_BUCKETS = {
    "hives/system/core": "HIGH",
    "hives/user/core": "HIGH",
    "hives/system/kape_exports": "HIGH",
    "hives/user/kape_exports": "HIGH",

    "databases": "MEDIUM",
    "text_reports": "MEDIUM",
    "configs": "MEDIUM",
    "event_logs": "MEDIUM",

    "other": "LOW",
}


def classify_sensitivity(record: dict) -> str:
    bucket = record.get("bucket", "")
    return SENSITIVE_BUCKETS.get(bucket, "LOW")


def generate_sensitivity_report(manifest_path: Path):
    records = load_manifest(manifest_path)

    counts = Counter()
    size_totals = Counter()

    for r in records:
        level = classify_sensitivity(r)
        counts[level] += 1
        size_totals[level] += r.get("size", 0)

    return counts, size_totals


def print_sensitivity_report(counts, sizes):
    print(" ===== SENSITIVITY REPORT ===== ")
    for level in ["HIGH", "MEDIUM", "LOW"]:
        print(f"{level:<10} | files: {
              counts[level]:>6} | bytes: {sizes[level]:>12}")


def filter_by_sensitivity(records, level):
    return [r for r in records if classify_sensitivity(r) == level]
