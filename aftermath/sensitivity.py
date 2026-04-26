# sensitivity.py

from collections import Counter
from pathlib import Path
from aftermath.manifest_query import load_manifest
from aftermath.registry_parse import parse_registry_hives_from_triage
from aftermath.registry_parse import (parse_registry_hives_from_triage, summarize_registry_findings,)


def generate_registry_findings_from_manifest(manifest_path: Path) -> dict[str, str]:
    triaged_root = manifest_path.parent
    return parse_registry_hives_from_triage(triaged_root)


SENSITIVE_BUCKETS = {
    "hives/system/core": "HIGH",
    "hives/user/core": "HIGH",
    "hives/system/kape_exports": "HIGH",
    "hives/user/kape_exports": "HIGH",

    "databases": "MEDIUM",
    "text_reports": "MEDIUM",
    "configs": "MEDIUM",
    "event_logs": "MEDIUM",
    "shortcuts": "MEDIUM",

    "pictures": "LOW",
    "pdfs": "LOW",
    "other": "LOW",
}


CREDENTIAL_KEYWORDS = [
    "password",
    "passwd",
    "pwd",
    "credential",
    "creds",
    "secret",
    "token",
    "apikey",
    "api_key",
    "privatekey",
    "private_key",
    "ssh",
    "rsa",
    "id_rsa",
    "wallet",
    "login",
    "logins",
    "keychain",
]


EMAIL_KEYWORDS = [
    "email",
    "mailbox",
    "outlook",
    "thunderbird",
    ".pst",
    ".ost",
]


BROWSER_KEYWORDS = [
    "history",
    "cookies",
    "cache",
    "webcache",
    "chrome",
    "edge",
    "firefox",
    "brave",
    "opera",
    "places.sqlite",
    "favicons.sqlite",
    "cookies.sqlite",
    "logins.json",
    "login data",
    "visited links",
]


HIGH_VALUE_BUCKETS = {
    "hives/system/core",
    "hives/user/core",
    "hives/system/kape_exports",
    "hives/user/kape_exports",
    "databases",
    "event_logs",
    "filesystem/ntfs",
}


LEVEL_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def bump_level(current: str, new: str) -> str:
    if LEVEL_RANK[new] > LEVEL_RANK[current]:
        return new
    return current


def record_text(record: dict) -> str:
    return " ".join([
        record.get("bucket", ""),
        record.get("relative_source", ""),
        record.get("relative_destination", ""),
        record.get("src", ""),
    ]).lower()


def classify_record(record: dict) -> tuple[str, list[str]]:
    bucket = record.get("bucket", "")
    text = record_text(record)

    level = SENSITIVE_BUCKETS.get(bucket, "LOW")
    reasons = []

    if bucket in HIGH_VALUE_BUCKETS:
        reasons.append(f"High-value forensic bucket: {bucket}")

    if any(word in text for word in CREDENTIAL_KEYWORDS):
        level = bump_level(level, "HIGH")
        reasons.append("Possible credential/secret artifact")

    if any(word in text for word in EMAIL_KEYWORDS):
        level = bump_level(level, "MEDIUM")
        reasons.append("Possible email artifact")

    if any(word in text for word in BROWSER_KEYWORDS):
        level = bump_level(level, "HIGH")
        reasons.append("Possible browser history/cache/credential artifact")

    if bucket in {"hives/system/core", "hives/user/core", "hives/system/kape_exports", "hives/user/kape_exports"}:
        level = bump_level(level, "HIGH")
        reasons.append("Registry hive or registry export")

    if bucket == "databases":
        reasons.append("Database file may contain application or browser data")

    if bucket == "event_logs":
        reasons.append("Windows event log artifact")

    if not reasons:
        reasons.append("General triaged artifact")

    return level, reasons


def classify_sensitivity(record: dict) -> str:
    level, _ = classify_record(record)
    return level


def generate_sensitivity_report(manifest_path: Path):
    records = load_manifest(manifest_path)

    counts = Counter()
    size_totals = Counter()
    flagged = []

    for record in records:
        level, reasons = classify_record(record)

        counts[level] += 1
        size_totals[level] += record.get("size", 0)

        if level in {"HIGH", "MEDIUM"}:
            flagged.append({
                "level": level,
                "reasons": reasons,
                "record": record,
            })

    flagged.sort(
        key=lambda item: (
            LEVEL_RANK[item["level"]],
            item["record"].get("size", 0),
        ),
        reverse=True,
    )

    registry_findings = generate_registry_findings_from_manifest(manifest_path)

    return counts, size_totals, flagged, registry_findings


def print_sensitivity_report(counts, sizes, flagged, registry_findings, limit: int = 25):
    print(" ===== SENSITIVITY / PRIORITY REPORT ===== ")
    print()

    print("Summary:")
    for level in ["HIGH", "MEDIUM", "LOW"]:
        print(f"{level:<10} | files: {counts[level]:>6} | bytes: {sizes[level]:>12}")

    print()
    print(f"Top flagged artifacts for review: {min(len(flagged), limit)} shown")
    print()

    if not flagged:
        print("No high or medium priority artifacts were flagged.")
    else:
        for i, item in enumerate(flagged[:limit], start=1):
            record = item["record"]

            print(f"[{i}] {item['level']}")
            print(f"    bucket               : {record.get('bucket', '')}")
            print(f"    relative_source      : {record.get('relative_source', '')}")
            print(f"    relative_destination : {record.get('relative_destination', '')}")
            print(f"    size                 : {record.get('size', '')}")
            print(f"    sha256               : {record.get('sha256', '')}")
            print("    reason(s):")

            for reason in item["reasons"]:
                print(f"      - {reason}")

            print()

        print()
    print(" ===== REGISTRY ANALYST SUMMARY ===== ")
    print()

    if not registry_findings:
        print("No registry hive findings available.")
        return

    for line in summarize_registry_findings(registry_findings):
        print(line)

    print()
    print(" ===== RAW REGISTRY DETAILS ===== ")
    print()

    for path, report in registry_findings.items():
        print(report)
        print("=" * 80)

def filter_by_sensitivity(records, level):
    return [r for r in records if classify_sensitivity(r) == level]
