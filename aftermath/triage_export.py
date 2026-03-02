from pathlib import Path

SYSTEM_HIVES = {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "HARDWARE"}
USER_HIVES = {"NTUSER.DAT", "USERCLASS.DAT"}

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif",
              ".bmp", ".tif", ".tiff", ".webp", ".heic"}
PDF_EXTS = {".pdf"}
DB_EXTS = {".sqlite", ".db"}
PREFETCH_EXTS = {".pf"}
LNK_EXTS = {".lnk"}


# 
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
