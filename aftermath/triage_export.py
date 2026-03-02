import hashlib
import json
import shutil
from pathlib import Path

SYSTEM_HIVES = {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "HARDWARE"}
USER_HIVES = {"NTUSER.DAT", "USRCLASS.DAT"}

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif",
              ".bmp", ".tif", ".tiff", ".webp", ".heic"}
PDF_EXTS = {".pdf"}
DB_EXTS = {".sqlite", ".db"}
PREFETCH_EXTS = {".pf"}
LNK_EXTS = {".lnk"}


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def classify_file(p: Path) -> str:

    name, ext = p.name.upper(), p.suffix.lower()

    if name in SYSTEM_HIVES:
        return "hives/system"

    if name in USER_HIVES:
        return "hives/user"

    if ext in PREFETCH_EXTS:
        return "prefetch"

    if ext in LNK_EXTS:
        return "shortcuts"

    if ext in IMAGE_EXTS:
        return "pictures"

    if ext in PDF_EXTS:
        return "pdfs"

    if ext in DB_EXTS:
        return "databases"

    return "other"


def export_triaged(kape_path: Path, out_path: Path) -> dict:
    # create folders
    out_path.mkdir(parents=True, exist_ok=True)

    bucket_counts: dict[str, int] = {}
    manifest = out_path / "manifest.jsonl"

    for p in kape_path.rglob('*'):
        # exit section before trying to define a folder
        if not p.is_file():
            continue

        # stores path for triaged folder. e.g.  'hives/system'
        bucket = classify_file(p)
        bucket_dir = out_path / bucket
        bucket_dir.mkdir(parents=True, exist_ok=True)

        dest = bucket_dir / p.name

        # collisions handling
        if dest.exists():
            stem = p.stem
            suffix = p.suffix  # includes leading dot, or "" if none
            n = 2
            while True:
                candidate = bucket_dir / f"{stem}__{n}{suffix}"
                if not candidate.exists():
                    dest = candidate
                    break
                n += 1
        src_sha256 = sha256_file(p)

        shutil.copy2(p, dest)
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1

        # Input into manifest
        record = {
            "bucket": bucket,
            "relative_source": str(p.relative_to(kape_path)),
            "src": str(p),
            "relative_destination": str(dest.relative_to(out_path)),
            "size": p.stat().st_size,
            "sha256": src_sha256,
        }

        with manifest.open("a", encoding="utf-8") as man:
            man.write(json.dumps(record) + "\n")

    return bucket_counts
