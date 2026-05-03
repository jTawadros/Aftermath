from pathlib import Path


def is_valid_dir(path: Path) -> Path | None:
    if not path.exists():
        print("Path does not exist.")
        return None
    if path.is_dir():
        print("Path exists...")
        print("Validating with KAPE heuristics")
        if is_valid_kape_output(path):
            print("Confirmed KAPE-like layout")
            return path
        print("Directory does not match what is expected of a KAPE output")
        return None
    print("Unsupported input.")
    return None


SYSTEM_HIVES = {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "HARDWARE"}
USER_HIVES = {"NTUSER.DAT", "USRCLASS.DAT"}


def is_valid_kape_output(path: Path) -> bool:
    if not path.exists() or not path.is_dir():
        return False

    score = 0
    file_count = 0

    has_consolelog = False
    has_registry_export = False
    has_hive = False
    has_prefetch = False
    has_eventlog = False
    has_shortcut = False

    for p in path.rglob("*"):
        if not p.is_file():
            continue

        file_count += 1
        name_upper = p.name.upper()
        suffix_lower = p.suffix.lower()

        if "CONSOLELOG" in name_upper:
            has_consolelog = True

        if name_upper.startswith("_REGISTRY_MACHINE_") or name_upper.startswith("_REGISTRY_USER_"):
            has_registry_export = True

        if name_upper in SYSTEM_HIVES or name_upper in USER_HIVES:
            has_hive = True

        if suffix_lower == ".pf":
            has_prefetch = True

        if suffix_lower == ".evtx":
            has_eventlog = True

        if suffix_lower == ".lnk":
            has_shortcut = True

    if file_count == 0:
        return False

    if has_consolelog:
        score += 3
    if has_registry_export:
        score += 2
    if has_hive:
        score += 2
    if has_prefetch:
        score += 1
    if has_eventlog:
        score += 1
    if has_shortcut:
        score += 1

    return score >= 3
