from pathlib import Path
from aftermath.manifest_query import load_manifest
from aftermath.triage_export import sha256_file


def verify_manifest_integrity(manifest_path: Path):
    records = load_manifest(manifest_path)

    base_dir = manifest_path.parent
    mismatches = []
    missing = []

    for r in records:
        rel_dest = r.get("relative_destination")
        expected_hash = r.get("sha256")

        file_path = base_dir / rel_dest

        if not file_path.exists():
            missing.append(rel_dest)
            continue

        actual_hash = sha256_file(file_path)

        if actual_hash != expected_hash:
            mismatches.append((rel_dest, expected_hash, actual_hash))

    return mismatches, missing


def print_integrity_results(mismatches, missing):
    print(" ===== INTEGRITY CHECK ===== ")

    if not mismatches and not missing:
        print("All files verified successfully.")
        return

    if missing:
        print(f"\nMissing files ({len(missing)}):")
        for f in missing[:10]:
            print(f"  {f}")

    if mismatches:
        print(f"\nHash mismatches ({len(mismatches)}):")
        for f, exp, act in mismatches[:10]:
            print(f"  {f}")
            print(f"    expected: {exp}")
            print(f"    actual  : {act}")
