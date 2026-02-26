import pathlib
from pathlib import Path

def scan_folders(path: Path) -> dict:
    files_by_extensions = {}
    total_file_count = 0
    total_bytes = 0

    for p in path.rglob("*"):
        if p.is_file():
            ext = p.suffix.lower()
            if not ext:
                ext = "no_extension"
            files_by_extensions[ext] = files_by_extensions.get(ext, 0) + 1
            total_file_count += 1
            total_bytes += p.stat().st_size
    return {
        "total_files": total_file_count,
        "total_bytes": total_bytes,
        "extension_counts": files_by_extensions
    }

