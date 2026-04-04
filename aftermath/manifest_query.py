import json
from pathlib import Path


def load_manifest(manifest_path: Path) -> list[dict]:
    records = []

    with manifest_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))

    return records


def record_matches(
    record: dict,
    bucket: str | None = None,
    name: str | None = None,
    contains: str | None = None,
    sha256: str | None = None,
    min_size: int | None = None,
    max_size: int | None = None,
) -> bool:
    if bucket and record.get("bucket") != bucket:
        return False

    if sha256 and record.get("sha256") != sha256:
        return False

    size = record.get("size", 0)
    if min_size is not None and size < min_size:
        return False
    if max_size is not None and size > max_size:
        return False

    relative_source = record.get("relative_source", "")
    relative_destination = record.get("relative_destination", "")

    if name:
        name_lower = name.lower()
        src_name = Path(relative_source).name.lower()
        dst_name = Path(relative_destination).name.lower()
        if name_lower != src_name and name_lower != dst_name:
            return False

    if contains:
        contains_lower = contains.lower()
        haystack = " ".join([
            record.get("relative_source", ""),
            record.get("relative_destination", ""),
            record.get("src", ""),
            record.get("bucket", ""),
        ]).lower()
        if contains_lower not in haystack:
            return False

    return True


def query_manifest(
    manifest_path: Path,
    bucket: str | None = None,
    name: str | None = None,
    contains: str | None = None,
    sha256: str | None = None,
    min_size: int | None = None,
    max_size: int | None = None,
    limit: int | None = None,
) -> list[dict]:
    records = load_manifest(manifest_path)

    matches = []
    for record in records:
        if record_matches(
            record,
            bucket=bucket,
            name=name,
            contains=contains,
            sha256=sha256,
            min_size=min_size,
            max_size=max_size,
        ):
            matches.append(record)
            if limit is not None and len(matches) >= limit:
                break

    return matches


def print_manifest_results(results: list[dict]) -> None:
    if not results:
        print("No matching manifest records found.")
        return

    print(f"Found {len(results)} matching record(s):")
    print()

    for i, record in enumerate(results, start=1):
        print(f"[{i}] bucket: {record.get('bucket', '')}")
        print(f"    relative_source      : {record.get('relative_source', '')}")
        print(f"    relative_destination : {record.get('relative_destination', '')}")
        print(f"    size                 : {record.get('size', '')}")
        print(f"    sha256               : {record.get('sha256', '')}")
        print()
